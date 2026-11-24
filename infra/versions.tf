terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.92"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # État Terraform stocké et verrouillé par GitLab (chiffré, accès selon les
  # rôles du projet). Jamais de .tfstate dans le dépôt : il contient des secrets.
  # Configuration fournie par les variables TF_HTTP_* (voir .gitlab-ci.yml).
  backend "http" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Owner     = "devsecops-team"
    }
  }
}
