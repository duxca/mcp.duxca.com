variable "project_id" {
  description = "Google CloudプロジェクトのプロジェクトID"
  type        = string
}

variable "region" {
  description = "デプロイするリージョン"
  type        = string
  default     = "asia-northeast1"
}

variable "service_name" {
  description = "Cloud Runサービスの名前"
  type        = string
  default     = "mcp-duxca-com"
}

variable "container_image" {
  description = "デプロイするコンテナイメージのURL"
  type        = string
}

variable "github_client_id" {
  description = "GitHub OAuth client ID"
  type        = string
}

variable "oauth_redirect_allowlist" {
  description = "OAuth redirect_uri allowlist (comma-separated). Replaces the code defaults when set."
  type        = string
}

variable "github_client_secret_version" {
  description = "Secret Manager version for GITHUB_CLIENT_SECRET"
  type        = string
  default     = "latest"
}

variable "terraform_state_bucket" {
  description = "Terraform remote state bucket"
  type        = string
  default     = "mcp-duxca-prod-terraform-state"
}

variable "storage_state_prefix" {
  description = "Terraform remote state prefix for terraform_gcp_storage"
  type        = string
  default     = "mcp.duxca.com/gcp_storage"
}
