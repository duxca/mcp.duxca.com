variable "project_id" {
  description = "Google Cloud project ID"
  type        = string
}

variable "github_repositories" {
  description = "GitHub repositories allowed to impersonate the deployer service account from main"
  type        = list(string)
}

variable "github_repository_id" {
  description = "Numeric GitHub repository ID allowed to impersonate the deployer (immutable, unlike the name)"
  type        = string
}

variable "github_repository_owner_id" {
  description = "Numeric GitHub repository owner ID allowed to impersonate the deployer"
  type        = string
}

variable "deploy_workflow_path" {
  description = "Workflow file allowed to impersonate the deployer, as it appears in the job_workflow_ref claim"
  type        = string
  default     = "duxca/mcp.duxca.com/.github/workflows/deploy-cloudrun.yml"
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
