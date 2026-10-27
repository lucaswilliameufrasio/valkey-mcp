# Sign-in boundary

- **Reach:** open `/` in a fresh local browser profile.
- **Drive:** inspect the logged-out product name, SSO action, and visible OIDC setup state. Do not activate SSO during routine verification.
- **Proof:** screenshot of the rendered Valkey MCP sign-in page; this does not prove authentication.
- **Preconditions:** local UI server; API configuration is available only when the documented backend is running.
- **Gotcha:** login proceeds to the external identity provider and requires explicit scope/credentials.
