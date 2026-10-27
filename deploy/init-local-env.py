import os
import secrets
from pathlib import Path


root = Path(__file__).resolve().parent.parent
example_path = root / ".env.docker.example"
env_path = root / ".env"
if env_path.exists():
    raise SystemExit("Refusing to overwrite the existing .env file.")

values = {
    line.split("=", 1)[0]: line.split("=", 1)[1]
    for line in example_path.read_text(encoding="utf-8").splitlines()
    if "=" in line
}
values.update(
    {
        "MCP_OAUTH_STATE_KEY": secrets.token_urlsafe(48),
        "OIDC_BOOTSTRAP_ADMIN_SUBJECTS": "dev-admin",
        "VAULT_ROOT_TOKEN": secrets.token_urlsafe(48),
        "VAULT_ADMIN_TOKEN": secrets.token_urlsafe(48),
        "VAULT_RUNTIME_TOKEN": secrets.token_urlsafe(48),
    }
)
content = "".join(f"{key}={value}\n" for key, value in values.items())
descriptor = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as env_file:
    env_file.write(content)
print("Created a private local .env with generated credentials.")
