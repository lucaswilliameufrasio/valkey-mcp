path "integration-secrets/data/*" {
  capabilities = ["create", "read", "update"]
}

path "integration-secrets/metadata/*" {
  capabilities = ["read", "delete"]
}
