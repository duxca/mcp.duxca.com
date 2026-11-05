# Service Account for Cloud Run
resource "google_service_account" "mcp_container" {
  account_id   = "mcp-container"
  display_name = "MCP Container Service Account"
  description  = "Service account for the mcp.duxca.com gateway running on Cloud Run"
}
