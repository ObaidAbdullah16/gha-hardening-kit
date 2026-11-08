# Example: a role that can only sync one S3 bucket, assumable only from the
# "production" environment of one repository.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

variable "site_bucket" {
  type    = string
  default = "my-company-site"
}

data "aws_iam_policy_document" "deploy_site" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.site_bucket}"]
  }
  statement {
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:GetObject"]
    resources = ["arn:aws:s3:::${var.site_bucket}/*"]
  }
}

module "github_deploy_role" {
  source = "../../github-oidc-role"

  role_name          = "github-deploy-site"
  repositories       = ["my-org/website"]
  subjects           = ["environment:production"]
  inline_policy_json = data.aws_iam_policy_document.deploy_site.json
  tags               = { ManagedBy = "terraform" }
}

output "role_arn" {
  value = module.github_deploy_role.role_arn
}
