variable "project_id" {
  description = "Google Cloud project ID"
  type        = string
}

variable "github_repositories" {
  description = "GitHub repositories allowed to impersonate the deployer service account from main"
  type        = list(string)
}

variable "workload_identity_pool_id" {
  description = "Workload Identity Pool ID for GitHub Actions"
  type        = string
  default     = "githubaction"
}

variable "workload_identity_provider_id" {
  description = "Workload Identity Provider ID for GitHub Actions"
  type        = string
  default     = "github"
}

variable "deployer_service_account_id" {
  description = "GitHub Actions deployer service account ID"
  type        = string
  default     = "github-action-mcp"
}

variable "terraform_state_bucket" {
  description = "Terraform state bucket name"
  type        = string
  default     = "mcp-duxca-prod-terraform-state"
}

variable "app_service_account_email" {
  description = "Cloud Run runtime service account email"
  type        = string
}
