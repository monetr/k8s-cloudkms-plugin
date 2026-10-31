# APIs the plugin talks to: STS for the JWT exchange, IAM Credentials for
# service account impersonation, and Cloud KMS itself.
resource "google_project_service" "services" {
  for_each = toset([
    "cloudkms.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
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

# --- The service account the hosts impersonate --------------------------------

resource "google_service_account" "plugin" {
  account_id   = var.service_account_id
  display_name = "k8s-cloudkms-plugin"
  description  = "Encrypts/decrypts Kubernetes secrets. Impersonated by TPM-authenticated hosts."
}

# Each host's federated identity may mint access tokens for the service account.
# Granted per host (not to the whole pool) so the binding list says exactly who.
resource "google_service_account_iam_member" "host_impersonation" {
  for_each = var.hosts

  service_account_id = google_service_account.plugin.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.plugin.name}/subject/${each.key}"

  # The subject only exists once its provider does.
  depends_on = [google_iam_workload_identity_pool_provider.host]
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

# The plugin only uses cloudkms.cryptoKeyVersions.useToEncrypt and
# useToDecrypt (including its healthz TestIamPermissions check), which is
# exactly this role. Scoped to the key ring, so nothing outside it.
resource "google_kms_key_ring_iam_member" "plugin" {
  key_ring_id = google_kms_key_ring.plugin.id
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member      = google_service_account.plugin.member
}
