# Amazon Linux 2023 : agent SSM et AWS CLI préinstallés, mises à jour de sécurité suivies par AWS
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# IP publique fixe : l'URL de l'application ne change pas si l'instance est recréée
resource "aws_eip" "app" {
  domain = "vpc"
  tags   = { Name = "${var.project}-eip" }
}

locals {
  # Nom de domaine gratuit pointant sur l'EIP (ex. 3-91-10-20.sslip.io), nécessaire pour un certificat TLS
  app_domain = "${replace(aws_eip.app.public_ip, ".", "-")}.sslip.io"
  registry   = split("/", aws_ecr_repository.app.repository_url)[0]
}

resource "aws_instance" "app" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = local.instance_profile_name
  ebs_optimized          = true
  monitoring             = true

  # IMDSv2 obligatoire ; hop limit 1 = les conteneurs ne peuvent pas joindre l'IMDS
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.main.arn
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region      = var.region
    project     = var.project
    registry    = local.registry
    repo_url    = aws_ecr_repository.app.repository_url
    domain      = local.app_domain
    caddy_image = var.caddy_image
    acme_email  = var.acme_email
  })
  user_data_replace_on_change = true

  tags = { Name = "${var.project}-app" }

  lifecycle {
    ignore_changes = [ami] # pas de recréation surprise à chaque nouvelle AMI
  }
}

resource "aws_eip_association" "app" {
  instance_id   = aws_instance.app.id
  allocation_id = aws_eip.app.id
}

# Résilience : récupération automatique de l'instance en cas de panne matérielle AWS
resource "aws_cloudwatch_metric_alarm" "auto_recover" {
  alarm_name          = "${var.project}-auto-recover"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  dimensions          = { InstanceId = aws_instance.app.id }
  alarm_actions       = ["arn:aws:automate:${var.region}:ec2:recover"]
}

# Redémarrage automatique si le système invité ne répond plus
resource "aws_cloudwatch_metric_alarm" "auto_reboot" {
  alarm_name          = "${var.project}-auto-reboot"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_Instance"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  dimensions          = { InstanceId = aws_instance.app.id }
  alarm_actions       = ["arn:aws:automate:${var.region}:ec2:reboot"]
}
