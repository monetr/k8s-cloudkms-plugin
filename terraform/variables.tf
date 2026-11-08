variable "project_id" {
  description = "Project that holds the workload identity pool and KMS key ring."
  type        = string
}

variable "hosts" {
  description = <<-EOT
    Hosts that run k8s-cloudkms-plugin. Each one gets its own workload identity
    pool provider holding only that host's public key, read from
    jwks/<host>.jwks.json (the output of `tpm-wif-key create`). Names are used as
    provider IDs and JWT subjects: 4-32 chars of [a-z0-9-], not starting with "gcp-".
  EOT
  type        = set(string)
  default     = ["node-1", "node-2", "node-3"]

  validation {
    condition     = alltrue([for h in var.hosts : can(regex("^[a-z0-9-]{4,32}$", h)) && !startswith(h, "gcp-")])
    error_message = "Host names must be 4-32 characters of [a-z0-9-] and must not start with \"gcp-\"."
  }
}

variable "jwt_issuer" {
  description = "Issuer the plugin puts in its JWTs (--jwt-issuer). Never fetched; it only has to match."
  type        = string
  default     = "https://tpm.k8s-cloudkms-plugin.internal"
}

variable "pool_id" {
  description = "Workload identity pool ID."
  type        = string
  default     = "k8s-cloudkms-plugin"
}

variable "kms_location" {
  description = "Location of the KMS key ring."
  type        = string
  default     = "us-central1"
}

variable "key_ring_name" {
  description = "Name of the KMS key ring."
  type        = string
  default     = "kubernetes"
}

variable "crypto_key_name" {
  description = "Name of the key, inside the key ring, that encrypts Kubernetes secrets. Each host is granted this key only."
  type        = string
  default     = "secrets"
}

# Boot-state binding. Only used to build plugin_args: set these to the same
# policy the hosts' keys were created with (`tpm-wif-key create -pcrs` and
# `-pcr-public-key`), or leave them empty for unbound keys.
variable "tpm_key_pcrs" {
  description = "Value for --tpm-key-pcrs, for example \"7\". Empty if the keys aren't bound to fixed PCR values."
  type        = string
  default     = ""
}

variable "tpm_pcr_public_key" {
  description = "Path on the hosts for --tpm-pcr-public-key, for example \"/etc/k8s-cloudkms-plugin/pcr-public-key.pem\". Empty if the keys don't accept signed PCR policies."
  type        = string
  default     = ""
}
