# APIs the plugin talks to: STS for the JWT exchange, and Cloud KMS itself.
# (With --impersonate-service-account, also enable
# iamcredentials.googleapis.com; see the README.)
resource "google_project_service" "services" {
  for_each = toset([
    "cloudkms.googleapis.com",
    "iam.googleapis.com",
    "sts.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# --- Identity: one pool, one provider (and one public key) per host ----------

resource "google_iam_workload_identity_pool" "plugin" {
  workload_identity_pool_id = var.pool_id
  display_name              = "k8s-cloudkms-plugin hosts"
  description               = "Hosts that authenticate with a TPM-resident key."

  depends_on = [google_project_service.services]
}

resource "google_iam_workload_identity_pool_provider" "host" {
  for_each = var.hosts

  workload_identity_pool_id          = google_iam_workload_identity_pool.plugin.workload_identity_pool_id
  workload_identity_pool_provider_id = each.key
  display_name                       = each.key
  description                        = "TPM key for ${each.key}"

  # Set to true to cut this host off without deleting anything. New token
  # exchanges fail immediately; already-issued access tokens expire within 1h.
  disabled = false

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  # This provider only holds this host's key, so a host can only ever present
  # its own subject; this also keeps audit logs honest.
  attribute_condition = "assertion.sub == \"${each.key}\""

  oidc {
    issuer_uri = var.jwt_issuer
    # Public key only. Produced on the host by `tpm-wif-key create`.
    jwks_json = file("${path.module}/jwks/${each.key}.jwks.json")
  }
}

# --- KMS ---------------------------------------------------------------------

resource "google_kms_key_ring" "plugin" {
  name     = var.key_ring_name
  location = var.kms_location

  depends_on = [google_project_service.services]
}

resource "google_kms_crypto_key" "secrets" {
  name     = var.crypto_key_name
  key_ring = google_kms_key_ring.plugin.id
  purpose  = "ENCRYPT_DECRYPT"

  # Destroying this key makes every secret encrypted with it unrecoverable.
  lifecycle {
    prevent_destroy = true
  }
}

# Each host's federated identity uses the key directly, with no service account
# in between. The plugin only uses cloudkms.cryptoKeyVersions.useToEncrypt and
# useToDecrypt (including its healthz TestIamPermissions check), which this
# role covers. Scoped to the one key.
#
# Granted per host, not to the whole pool (principalSet://.../*), so a host
# added to the pool for something else, such as a test host, doesn't get this
# key. The provider's attribute_condition is what makes this safe: only this
# host's key can produce this host's subject. An allow policy holds at most
# 1,500 principals.
resource "google_kms_crypto_key_iam_member" "host" {
  for_each = var.hosts

  crypto_key_id = google_kms_crypto_key.secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.plugin.name}/subject/${each.key}"

  # The subject only exists once its provider does.
  depends_on = [google_iam_workload_identity_pool_provider.host]
}
