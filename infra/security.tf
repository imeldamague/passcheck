data "aws_caller_identity" "current" {}

# ---- Clé KMS du projet (rotation annuelle automatique) ----
data "aws_iam_policy_document" "kms" {
  # Dans une politique de clé KMS, Resource "*" désigne la clé elle-même (norme AWS)
  #checkov:skip=CKV_AWS_111:Politique de cle KMS, resource "*" = cette cle uniquement
  #checkov:skip=CKV_AWS_356:Politique de cle KMS, resource "*" = cette cle uniquement
  #checkov:skip=CKV_AWS_109:Administration de la cle reservee au compte proprietaire
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    # Le rôle de l'instance peut déchiffrer ses secrets SSM (accord direct dans la politique de clé)
    sid       = "InstanceDecrypt"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.instance_role_arn]
    }
  }
  statement {
    sid = "LogDeliveryToS3"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "${var.project} - chiffrement EBS, ECR, SSM, logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.main.key_id
}

# ---- Pare-feu de l'instance : seulement HTTP/HTTPS entrants, aucun SSH ----
resource "aws_security_group" "web" {
  name        = "${var.project}-web"
  description = "HTTPS public, HTTP pour redirection et challenge ACME"
  #checkov:skip=CKV_AWS_260:Port 80 requis pour la redirection 301 vers HTTPS et le challenge Let's Encrypt HTTP-01 ; aucune donnee servie en clair
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS public"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP : redirection 301 vers HTTPS + challenge ACME LetsEncrypt"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS sortant : ECR, SSM, LetsEncrypt, mises a jour"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP sortant : depots de paquets"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-web" }
}

# ---- Secret applicatif (clé de signature des sessions Flask) ----
resource "random_password" "secret_key" {
  length  = 64
  special = false
}

resource "aws_ssm_parameter" "secret_key" {
  name   = "/${var.project}/secret_key"
  type   = "SecureString"
  key_id = aws_kms_key.main.arn
  value  = random_password.secret_key.result
}

# Version de l'image à déployer : mise à jour par la pipeline à chaque release
resource "aws_ssm_parameter" "image_tag" {
  name   = "/${var.project}/image_tag"
  type   = "SecureString"
  key_id = aws_kms_key.main.arn
  value  = "none"
  lifecycle { ignore_changes = [value] }
}
