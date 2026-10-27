# Connections and grants

- **Reach:** sign in locally as an administrator, then open `/valkey`.
- **Drive:** create a disposable local Valkey connection and grant a test principal a narrow key prefix and the minimum access level.
- **Proof:** saved target and grant are visible; confirm them through the isolated API and exercise a key operation within the granted prefix. Verify an out-of-prefix operation is denied when supported by the local harness.
- **Preconditions:** isolated Valkey MCP stack, disposable Valkey server, Vault bootstrap, and test identities.
- **Gotcha:** never use production credentials; a success message alone does not prove broker behavior.
