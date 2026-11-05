terraform {
  required_version = ">= 1.0.0"

  backend "gcs" {
    bucket = "mcp-duxca-prod-terraform-state"
    prefix = "mcp.duxca.com/cf"
  }

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.19.1"
    }
  }
}
