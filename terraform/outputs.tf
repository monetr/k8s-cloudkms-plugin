output "service_account_email" {
  value = google_service_account.plugin.email
}

output "key_uri" {
  description = "Value for --key-uri."
  value       = google_kms_crypto_key.secrets.id
}

# Ready-to-use plugin flags for each host.
output "plugin_args" {
  value = {
    for host, provider in google_iam_workload_identity_pool_provider.host : host => join(" ", [
      "--key-uri=${google_kms_crypto_key.secrets.id}",
      "--wif-provider=${provider.name}",
      "--jwt-issuer=${var.jwt_issuer}",
      "--jwt-subject=${host}",
      "--impersonate-service-account=${google_service_account.plugin.email}",
    ])
  }
}
