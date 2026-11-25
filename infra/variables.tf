variable "region" {
  description = "Région AWS de la sandbox"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Nom du projet (préfixe des ressources)"
  type        = string
  default     = "passcheck"
}

variable "instance_type" {
  description = "Type d'instance (t3 : supporte EBS-optimized)"
  type        = string
  default     = "t3.micro"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}

variable "caddy_image" {
  description = "Image du reverse proxy TLS (version figée)"
  type        = string
  default     = "caddy:2.8.4-alpine"
}

variable "acme_email" {
  description = "E-mail de contact Let's Encrypt (optionnel)"
  type        = string
  default     = ""
}

# ---- Compatibilité AWS Academy Learner Lab ----
# Le Learner Lab interdit iam:CreateRole : on utilise le rôle fourni (LabRole).
# Sur un compte AWS normal, mettre false pour créer les rôles au moindre privilège.
variable "use_lab_role" {
  description = "true = Learner Lab (LabRole / LabInstanceProfile), false = rôles dédiés"
  type        = bool
  default     = true
}

variable "lab_role_name" {
  type    = string
  default = "LabRole"
}

variable "lab_instance_profile_name" {
  type    = string
  default = "LabInstanceProfile"
}
