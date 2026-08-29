path "transit/keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/sign/*" {
  capabilities = ["update"]
}
