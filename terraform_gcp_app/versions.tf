terraform {
  required_version = ">= 1.0.0"

  backend "gcs" {
    bucket = "mcp-duxca-prod-terraform-state"
    prefix = "mcp.duxca.com/gcp_app"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}
