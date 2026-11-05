provider "google" {
  project = var.project_id
  region  = var.region
}

# limits は ignore_changes に入れない（river と違う。DESIGN.md §6.4）
resource "google_cloud_run_service" "mcp" {
  name     = var.service_name
  location = var.region

  template {
    spec {
      container_concurrency = 128
      # ask の待機（最大 240 秒）と webhook の 5 秒に余裕を足す
      timeout_seconds = 300

      containers {
        image = var.container_image

        env {
          name  = "LITESTREAM_BUCKET"
          value = data.terraform_remote_state.storage.outputs.litestream_bucket_name
        }

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "GITHUB_CLIENT_ID"
          value = var.github_client_id
        }

        env {
          name = "GITHUB_CLIENT_SECRET"
          value_from {
            secret_key_ref {
              name = data.terraform_remote_state.storage.outputs.github_client_secret_id
              key  = var.github_client_secret_version
            }
          }
        }
      }

      service_account_name = data.terraform_remote_state.storage.outputs.mcp_container_service_account_email
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"         = "1"
        "autoscaling.knative.dev/minScale"         = "0"
        "run.googleapis.com/cpu-throttling"        = "true"
        "run.googleapis.com/execution-environment" = "gen1"
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  autogenerate_revision_name = true
}

resource "google_cloud_run_service_iam_member" "public_access" {
  service  = google_cloud_run_service.mcp.name
  location = google_cloud_run_service.mcp.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
