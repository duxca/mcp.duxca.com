variable "project_id" {
  description = "Google CloudプロジェクトのプロジェクトID"
  type        = string
}

variable "region" {
  description = "デプロイするリージョン"
  type        = string
  default     = "asia-northeast1"
}

variable "bucket_name" {
  description = "Litestream用のGCSバケット名"
  type        = string
}

variable "litestream_bucket_force_destroy" {
  description = "Litestream用GCSバケット内のオブジェクトごと削除するか"
  type        = bool
  default     = false
}

variable "docker_registry" {
  description = "Docker Artifact Registry リポジトリ名"
  type        = string
  default     = "cloud-run-source-deploy"
}
