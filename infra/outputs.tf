output "app_url" {
  description = "URL publique de l'application (HTTPS)"
  value       = "https://${local.app_domain}"
}

output "instance_id" {
  value = aws_instance.app.id
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "image_tag_parameter" {
  value = aws_ssm_parameter.image_tag.name
}
