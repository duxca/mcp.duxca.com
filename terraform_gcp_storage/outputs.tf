output "artifact_registry_location" {
  description = "Artifact Registry repository location"
  value       = google_artifact_registry_repository.docker_repo.location
}

output "artifact_registry_repository_id" {
  description = "Artifact Registry repository ID"
  value       = google_artifact_registry_repository.docker_repo.repository_id
}

output "artifact_registry_repository_url" {
  description = "Docker image path prefix (<location>-docker.pkg.dev/<project>/<repository>)"
  value       = "${google_artifact_registry_repository.docker_repo.location}-docker.pkg.dev/${google_artifact_registry_repository.docker_repo.project}/${google_artifact_registry_repository.docker_repo.repository_id}"
}

output "litestream_bucket_name" {
  description = "Litestreamレプリカ用GCSバケット名"
  value       = google_storage_bucket.litestream_bucket.name
}

output "mcp_container_service_account_email" {
  description = "Cloud Run service account email"
  value       = google_service_account.mcp_container.email
}

output "github_client_secret_id" {
  description = "Secret Manager secret ID for GITHUB_CLIENT_SECRET"
  value       = google_secret_manager_secret.github_client_secret.secret_id
}
