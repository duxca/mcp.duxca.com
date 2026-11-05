provider "cloudflare" {}

resource "cloudflare_dns_record" "mcp" {
  zone_id = var.cloudflare_zone_id
  name    = var.mcp_dns_name
  content = var.mcp_dns_content
  type    = "CNAME"
  proxied = false
  ttl     = 60
}
