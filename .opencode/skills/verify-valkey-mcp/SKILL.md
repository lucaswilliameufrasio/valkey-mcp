---
name: verify-valkey-mcp
description: Verify the standalone Valkey MCP admin UI and documented operator journeys.
---

# Verify Valkey MCP

## Launch

Primary surface: SvelteKit admin UI in `apps/admin`. From that directory run:

```sh
pnpm dev --port 5181
```

The UI proxies API, MCP, and OAuth discovery routes to `127.0.0.1:8080`. Authenticated workflows require the documented standalone Valkey stack, the SQL development Authentik network, and disposable Valkey/test data (see the root README). Do not load or print `.env` values. Without the stack, verify only the logged-out UI. Stop only this run's dev server with Ctrl-C.

## Preflight

1. In `apps/admin`, run `pnpm check` and `pnpm build`.
2. Check port ownership with `ss -ltnp 'sport = :5181'`; choose another free loopback port if occupied and leave unknown processes alone.
3. Start Vite, wait for its ready message, and confirm `http://127.0.0.1:5181/` and `/favicon.svg` both return HTTP 200.
4. Verify API/OIDC/Vault/Valkey readiness separately. A running UI server does not prove service readiness.

## Drive and evidence

Use Firefox at the local URL with accessible roles, names, and labels. Capture screenshots and relevant console/network errors in `artifacts/verification/`, preserving evidence after teardown. Do not activate SSO during routine UI checks. See [`features/README.md`](features/README.md); an unauthenticated screenshot proves only the sign-in boundary. Full operator journeys also require an isolated local API and broker result.

## Isolation, cleanup, and failures

Use a free loopback port and disposable local service data. Never use production credentials, kill processes by name, or remove resources not created for this run. Missing API, Authentik, Vault, or Valkey setup is a blocker, not a pass. Preserve artifacts and update the feature map when routes or behavior change.
