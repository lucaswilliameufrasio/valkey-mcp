# Valkey MCP UI feature map

Representative journeys only. See [`../SKILL.md`](../SKILL.md) for launch, preflight, and evidence rules. Operator workflows require isolated local services and a disposable Valkey target.

| Feature               | Route     | Primary actor | Proof                                                                 |
| --------------------- | --------- | ------------- | --------------------------------------------------------------------- |
| Sign-in boundary      | `/`       | Any user      | Logged-out product identity and SSO boundary render.                  |
| Connection and grants | `/valkey` | Administrator | Target and prefix-scoped grant are visible after saving.              |
| Audit trail           | `/audit`  | Administrator | Local operation outcomes appear with their recorded actor and target. |

Update this map when routes, labels, or permissions change.
