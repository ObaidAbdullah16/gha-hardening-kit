variable "role_name" {
  description = "Name of the IAM role GitHub Actions will assume."
  type        = string
}

variable "repositories" {
  description = "Repositories allowed to assume the role, as owner/name. No wildcards in the owner."
  type        = list(string)

  validation {
    # "repo:*:..." would trust workflows in ANY GitHub repository, including an attacker's.
    condition     = length(var.repositories) > 0 && alltrue([for r in var.repositories : can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", r))])
    error_message = "Each repository must be an exact owner/name, without wildcards."
  }
}

variable "subjects" {
  description = <<-EOT
    Which workflow runs may assume the role, as the part of the OIDC `sub` claim after `repo:<owner>/<name>:`.
    Examples: "ref:refs/heads/main", "environment:production", "ref:refs/tags/v*".
    Never use "*" - that would let any branch or pull request in.
  EOT
  type        = list(string)
  default     = ["ref:refs/heads/main"]

  validation {
    # Must name a branch, tag or environment, starting with a literal character: "ref:*",
    # "ref:refs/heads/*", "environment:*", "*" and "pull_request" are all refused.
    condition     = length(var.subjects) > 0 && alltrue([for s in var.subjects : can(regex("^(ref:refs/(heads|tags)/|environment:)[A-Za-z0-9._/-]", s))])
    error_message = "Subjects must be ref:refs/heads/<branch>, ref:refs/tags/<tag> or environment:<name>, without a leading wildcard. Never '*' or pull_request."
  }
}

variable "create_oidc_provider" {
  description = "Create the token.actions.githubusercontent.com provider. Set false if the account already has one."
  type        = bool
  default     = true
}

variable "managed_policy_arns" {
  description = "Managed policies to attach (keep this short)."
  type        = list(string)
  default     = []
}

variable "inline_policy_json" {
  description = "Optional least-privilege inline policy (JSON)."
  type        = string
  default     = null
}

variable "max_session_duration" {
  description = "Seconds. 3600 is plenty for most deploys."
  type        = number
  default     = 3600
}

variable "tags" {
  type    = map(string)
  default = {}
}
