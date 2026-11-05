variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for duxca.com"
  type        = string
}

variable "mcp_dns_name" {
  description = "DNS record name for the MCP Cloud Run domain mapping"
  type        = string
  default     = "mcp.duxca.com"
}

variable "mcp_dns_content" {
  description = "DNS CNAME target for the MCP Cloud Run domain mapping"
  type        = string
  default     = "ghs.googlehosted.com"
}
