project_id = "mcp-duxca-prod"
region     = "asia-northeast1"

service_name = "mcp-duxca-com"

# GitHub OAuth App（mcp-test と共有）の Client ID。GitHub Secret MCP_GITHUB_CLIENT_ID と同じ値を、最初の app apply の前に入れる
github_client_id = "Ov23liz8A0ImvIiDqmdl"

# redirect_uri allowlist (L-1): code defaults minus the unused chatgpt wildcard.
# grok.com stays a subtree entry: the Grok connector uses CIMD and its exact
# callback path is not enumerable from this repo, so it cannot be narrowed yet.
oauth_redirect_allowlist = "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,https://agent.meta.ai/api/hatch/oauth/callback,https://www.cursor.com/agents/mcp/oauth/callback,https://grok.com/,http://localhost/,http://127.0.0.1/,http://[::1]/"
