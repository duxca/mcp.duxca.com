# 土台側の API 有効化（旧 terraform_gcp_storage/main.tf から移管）

resource "google_project_service" "cloud_run_api" {
  service = "run.googleapis.com"
}

resource "google_project_service" "secret_manager_api" {
  service = "secretmanager.googleapis.com"
}

resource "google_project_service" "artifact_registry_api" {
  service = "artifactregistry.googleapis.com"
}

resource "google_project_service" "storage_api" {
  service = "storage.googleapis.com"
}
