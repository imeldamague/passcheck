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
