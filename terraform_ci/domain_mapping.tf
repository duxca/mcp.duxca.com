# deployer SA の run.developer には domainmappings の権限が無いので、
# 静的なドメインマッピングは app スタックではなく土台側で管理する。
# terraform_gcp_app の state から state mv で移した。import だと terraform_labels が
# 空で取り込まれ、goog-terraform-provisioned の付与が置き換え（ForceNew）になる
resource "google_cloud_run_domain_mapping" "mcp" {
  name     = "mcp.duxca.com"
  location = var.region

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name       = var.app_service_name
    certificate_mode = "AUTOMATIC"
  }
}
