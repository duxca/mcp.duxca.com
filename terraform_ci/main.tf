provider "google" {
  project = var.project_id
}

locals {
  deployer_service_account_email = "${var.deployer_service_account_id}@${var.project_id}.iam.gserviceaccount.com"
  deployer_member                = "serviceAccount:${local.deployer_service_account_email}"
  github_main_ref_principal      = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions.name}/attribute.ref/refs/heads/main"
  github_repository_condition    = join(" || ", [for repository in var.github_repositories : "attribute.repository == '${repository}'"])

  # 新規プロジェクトでは無効。WIF のトークン交換（sts）と SA の借用（iamcredentials）にも要る
  ci_services = toset([
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
  ])

  project_roles = toset([
    "roles/artifactregistry.admin",
    "roles/artifactregistry.writer",
    "roles/iam.serviceAccountAdmin",
    "roles/run.admin",
    "roles/secretmanager.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
  ])
}

resource "google_project_service" "ci" {
  for_each = local.ci_services

  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "deployer" {
  account_id   = var.deployer_service_account_id
  display_name = "GitHub Actions MCP deployer"

  depends_on = [google_project_service.ci]
}

resource "google_iam_workload_identity_pool" "github_actions" {
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "GitHub Actions"

  depends_on = [google_project_service.ci]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "GitHub"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
  }

  attribute_condition = "(${local.github_repository_condition}) && attribute.ref == 'refs/heads/main'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_actions_impersonation" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.github_main_ref_principal
}

resource "google_project_iam_member" "deployer_project_roles" {
  for_each = local.project_roles

  project = var.project_id
  role    = each.value
  member  = local.deployer_member
}

resource "google_storage_bucket_iam_member" "terraform_state_object_admin" {
  bucket = var.terraform_state_bucket
  role   = "roles/storage.objectAdmin"
  member = local.deployer_member
}

# Cloud Run のサービスを実行 SA で動かすための actAs。プロジェクト単位の serviceAccountUser は付けない
resource "google_service_account_iam_member" "app_service_account_user" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.app_service_account_email}"
  role               = "roles/iam.serviceAccountUser"
  member             = local.deployer_member
}
