# GCS bucket for Litestream database replicas.
resource "google_storage_bucket" "litestream_bucket" {
  name          = var.bucket_name
  location      = var.region
  force_destroy = var.litestream_bucket_force_destroy

  lifecycle {
    prevent_destroy = false
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      with_state                 = "ARCHIVED"
      days_since_noncurrent_time = 90
    }
    action {
      type = "Delete"
    }
  }

  uniform_bucket_level_access = true
  # DB には webhook の秘密が平文で入る（DESIGN.md §5.6）
  public_access_prevention = "enforced"

  depends_on = [google_project_service.storage_api]
}

resource "google_storage_bucket_iam_member" "bucket_object_admin" {
  bucket = google_storage_bucket.litestream_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.mcp_container.email}"
}
