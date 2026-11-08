output "role_arn" {
  description = "Put this in the repository variable AWS_ROLE_ARN."
  value       = aws_iam_role.this.arn
}

output "oidc_provider_arn" {
  value = local.provider_arn
}

output "allowed_subjects" {
  value = local.subjects
}
