# deployer SA へのリソース単位のバインディング（プロジェクトレベルの
# admin ロールを外し、必要な相手にだけ絞る）

# イメージの push はこのリポジトリだけ
resource "google_artifact_registry_repository_iam_member" "deployer_writer" {
  location   = google_artifact_registry_repository.docker_repo.location
  repository = google_artifact_registry_repository.docker_repo.name
  role       = "roles/artifactregistry.writer"
  member     = local.deployer_member
}

# デプロイ中の存在確認ステップ（gcloud secrets versions access）用
resource "google_secret_manager_secret_iam_member" "deployer_secret_access" {
  secret_id = google_secret_manager_secret.github_client_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.deployer_member
}

# Cloud Run の公開設定（allUsers の invoker）は静的なので土台側で管理する。
# app スタックに置くと deployer にサービス IAM の管理権限（run.admin）が要る
resource "google_cloud_run_service_iam_member" "public_access" {
  service  = var.app_service_name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
