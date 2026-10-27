import json
import os
from pathlib import Path


template_path = Path("/config/realm-template.json")
output_path = Path("/output/valkey-mcp-realm.json")
template = template_path.read_text(encoding="utf-8")
replacements = {
    "__CLIENT_ID__": os.environ["OIDC_CLIENT_ID"],
    "__MCP_PUBLIC_URL__": os.environ["MCP_PUBLIC_URL"],
    "__OIDC_USERNAME__": os.environ["OIDC_USERNAME"],
    "__OIDC_PASSWORD__": os.environ["OIDC_PASSWORD"],
    "__OIDC_SUBJECT__": os.environ["OIDC_SUBJECT"],
}
for marker, value in replacements.items():
    template = template.replace(marker, json.dumps(value)[1:-1])

realm = json.loads(template)
output_path.write_text(json.dumps(realm), encoding="utf-8")
output_path.chmod(0o444)
