data "terraform_remote_state" "storage" {
  backend = "gcs"

  config = {
    bucket = var.terraform_state_bucket
    prefix = var.storage_state_prefix
  }
}
