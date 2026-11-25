# Rôle de l'instance : moindre privilège (créé seulement si use_lab_role = false).
# En Learner Lab, l'instance utilise LabInstanceProfile (voir locals plus bas).
#  - SSM Session Manager (administration sans SSH ni port 22)
#  - lecture de l'image dans ECR
#  - lecture des deux paramètres SSM du projet
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  count = var.use_lab_role ? 0 : 1

  name               = "${var.project}-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  count = var.use_lab_role ? 0 : 1

  role       = aws_iam_role.instance[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"] # action non restreignable par ressource
    resources = ["*"]
  }
  statement {
    sid = "EcrPull"
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
    ]
    resources = [aws_ecr_repository.app.arn]
  }
  statement {
    sid     = "ReadAppParameters"
    actions = ["ssm:GetParameter"]
    resources = [
      aws_ssm_parameter.secret_key.arn,
      aws_ssm_parameter.image_tag.arn,
    ]
  }
  statement {
    sid       = "DecryptAppSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "instance" {
  count = var.use_lab_role ? 0 : 1

  name   = "${var.project}-app"
  role   = aws_iam_role.instance[0].id
  policy = data.aws_iam_policy_document.instance.json
}

resource "aws_iam_instance_profile" "instance" {
  count = var.use_lab_role ? 0 : 1

  name = "${var.project}-instance"
  role = aws_iam_role.instance[0].name
}

# ---- Learner Lab : rôle et profil fournis par AWS Academy ----
data "aws_iam_role" "lab" {
  count = var.use_lab_role ? 1 : 0
  name  = var.lab_role_name
}

data "aws_iam_instance_profile" "lab" {
  count = var.use_lab_role ? 1 : 0
  name  = var.lab_instance_profile_name
}

locals {
  instance_profile_name = var.use_lab_role ? data.aws_iam_instance_profile.lab[0].name : aws_iam_instance_profile.instance[0].name
  instance_role_arn     = var.use_lab_role ? data.aws_iam_role.lab[0].arn : aws_iam_role.instance[0].arn
  flow_logs_role_arn    = var.use_lab_role ? data.aws_iam_role.lab[0].arn : aws_iam_role.flow_logs[0].arn
}
