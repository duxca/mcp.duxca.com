resource "google_cloud_run_domain_mapping" "mcp" {
  name     = "mcp.duxca.com"
  location = var.region

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name       = google_cloud_run_service.mcp.name
    certificate_mode = "AUTOMATIC"
  }
}
