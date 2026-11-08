output "key_uri" {
  description = "Value for --key-uri."
  value       = google_kms_crypto_key.secrets.id
}

# Ready-to-use plugin flags for each host, including its boot-state policy.
output "plugin_args" {
  value = {
    for host, provider in google_iam_workload_identity_pool_provider.host : host => join(" ", compact([
      "--key-uri=${google_kms_crypto_key.secrets.id}",
      "--wif-provider=${provider.name}",
      "--jwt-issuer=${var.jwt_issuer}",
      "--jwt-subject=${host}",
      var.tpm_key_pcrs == "" ? "" : "--tpm-key-pcrs=${var.tpm_key_pcrs}",
      var.tpm_pcr_public_key == "" ? "" : "--tpm-pcr-public-key=${var.tpm_pcr_public_key}",
    ]))
  }
}
