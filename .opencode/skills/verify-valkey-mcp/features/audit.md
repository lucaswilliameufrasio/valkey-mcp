# Audit trail

- **Reach:** sign in locally as an administrator and open `/audit`.
- **Drive:** perform a disposable local operation and reload the audit view.
- **Proof:** the new event shows its outcome and relevant actor/target fields; confirm the API response corresponds to the test operation.
- **Preconditions:** isolated local API, test principal, target, and an operation that emits an audit event.
- **Gotcha:** an empty or unavailable audit feed without backend data is not evidence that audit behavior works.
