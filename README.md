# k8s-cloudkms-plugin (TPM-backed)

A wrapper around [GoogleCloudPlatform/k8s-cloudkms-plugin](https://github.com/GoogleCloudPlatform/k8s-cloudkms-plugin)
that authenticates to Google Cloud using a key held in the host's TPM 2.0, via
[Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers).

There is no service account key, no credential file, and no secret of any kind
on disk. Each host's private key is generated inside its TPM and cannot be
exported. Google only ever holds the public key. To cut a single host off from
Google Cloud, you remove its public key (or disable its provider).

The plugin itself is upstream's code, imported as a library. Only the way the
HTTP client gets its credentials is different.

## How it works

```
 host                                             Google Cloud
 ┌──────────────────────────────┐
 │ TPM: P-256 key (FixedTPM,    │
 │      FixedParent, never      │
 │      exportable)             │
 │   │ signs                    │
 │   ▼                          │   ES256 JWT      ┌─────────────────────────┐
 │ k8s-cloudkms-plugin ─────────┼─────────────────▶│ STS (sts.googleapis.com) │
 │   ▲                          │                  │ verifies JWT against the │
 │   │ federated access token   │◀─────────────────┤ provider's uploaded JWKS │
 │   │ (memory only)            │                  └─────────────────────────┘
 │   ▼                          │   access token   ┌─────────────────────────┐
 │ Cloud KMS encrypt/decrypt ───┼─────────────────▶│ Cloud KMS                │
 └──────────────────────────────┘                  └─────────────────────────┘
```

1. `tpm-wif-key create` asks the TPM to generate an ECDSA P-256 signing key and
   stores it at a persistent TPM handle. It prints the key's public JWK set.
2. You upload that JWK set to a Workload Identity Federation OIDC provider.
3. When the plugin needs an access token, it builds a JWT
   (`iss`, `sub`, `aud`, `iat`, `exp`), has the TPM sign it (ES256), and
   exchanges it with Google's STS for a federated access token. The JWT is
   short lived (5 minutes by default) and only ever exists in memory.
4. The access token is cached in memory and refreshed (with a fresh TPM
   signature) when it expires.

## Security properties and caveats

- **The private key can't be stolen.** It is created with `FixedTPM`,
  `FixedParent` and `SensitiveDataOrigin`, so the TPM will never export it.
  The plugin refuses to use a key at the handle that lacks these attributes.
- **The key can be *used* by anyone with TPM access on the live host.** Root,
  or anything that can open `/dev/tpmrm0`, can ask the TPM to sign tokens while
  they have that access. They just can't take the key off the machine. Restrict
  access to `/dev/tpmrm0` (by default it is owned by the `tss` group). The key
  has no password and no PCR (boot state) binding.
- **Revocation isn't instant.** Removing a host's key, or disabling its
  provider, stops *new* token exchanges right away. Access tokens that were
  already issued stay valid until they expire, which can be up to 1 hour.
- **You need one provider per host.** An uploaded JWKS can hold at most
  **8 keys**, and revoking a host means editing its provider. So give each
  host its own provider (or group up to 8 hosts per provider, if you're OK
  with editing a shared JWKS to revoke one). Google documents no limit on
  providers per workload identity pool.
- **Grant access to the pool, not to each host.** An allow policy (for
  example, the KMS key's) can hold at most 1,500 principals. Granting a
  `principalSet://…/workloadIdentityPools/POOL/*` once covers every host
  without using up that limit. Revocation still happens at the provider.

## Install

Each [release](https://github.com/monetr/k8s-cloudkms-plugin/releases)
publishes static linux/amd64 and linux/arm64 binaries of both tools, each with
a `.sha256` file. This downloads the latest release for the current
architecture, verifies the checksums, and installs both binaries to
`/usr/local/bin` (where the [systemd unit](deploy/systemd/k8s-cloudkms-plugin.service)
expects the plugin). If any download or checksum fails, it stops before
installing anything.

<!-- x-release-please-start-version -->
```sh
(
  set -euo pipefail
  VERSION="v1.1.0"
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
  BASE="https://github.com/monetr/k8s-cloudkms-plugin/releases/download/${VERSION}"
  cd "$(mktemp -d)"
  for bin in k8s-cloudkms-plugin tpm-wif-key; do
    curl -fsSLO "${BASE}/${bin}-${VERSION}-linux-${ARCH}"
    curl -fsSLO "${BASE}/${bin}-${VERSION}-linux-${ARCH}.sha256"
  done
  sha256sum -c ./*.sha256
  for bin in k8s-cloudkms-plugin tpm-wif-key; do
    sudo install -m 0755 "${bin}-${VERSION}-linux-${ARCH}" "/usr/local/bin/${bin}"
  done
)
```
<!-- x-release-please-end -->

The binaries also have build provenance attestations. Attestations are matched
by the file's SHA-256, not its name, so you can check the installed binaries
directly to confirm they were built by this repository's release workflow:

```sh
gh attestation verify /usr/local/bin/k8s-cloudkms-plugin --repo monetr/k8s-cloudkms-plugin
gh attestation verify /usr/local/bin/tpm-wif-key --repo monetr/k8s-cloudkms-plugin
```

## Build

Requires Go 1.26+.

```sh
go build -o bin/ ./cmd/...
```

This produces two binaries:

- `bin/tpm-wif-key` provisions the TPM key and prints its JWKS.
- `bin/k8s-cloudkms-plugin` is the KMS plugin.

## 1. Provision the TPM key (once per host)

```sh
sudo bin/tpm-wif-key create > node-1.jwks.json
```

This creates the key at persistent handle `0x81010101` (change it with
`-tpm-key-handle`). It refuses to overwrite an existing key at that handle. To
print the JWKS of a key that already exists:

```sh
sudo bin/tpm-wif-key jwks
```

`node-1.jwks.json` contains only the public key, so it is safe to commit or
pass around. The `kid` is the key's RFC 7638 thumbprint.

## 2. Configure Google Cloud

Pick an issuer string, for example `https://tpm.example.internal`. It never
has to resolve or serve anything. It only has to match the provider's
`issuer_uri` and the plugin's `--jwt-issuer`.

The examples below use pool `kms-nodes`, provider/host `node-1`, and project
number `123456789`.

### Terraform

```hcl
variable "project_number" {
  type = string
}

# Host name => path to that host's JWKS from `tpm-wif-key create`.
# Host names become provider IDs: 4-32 chars, [a-z0-9-], no "gcp-" prefix.
variable "nodes" {
  type = map(string)
  default = {
    "node-1" = "jwks/node-1.jwks.json"
    "node-2" = "jwks/node-2.jwks.json"
  }
}

variable "issuer" {
  type    = string
  default = "https://tpm.example.internal"
}

resource "google_iam_workload_identity_pool" "kms_nodes" {
  workload_identity_pool_id = "kms-nodes"
  display_name              = "KMS plugin nodes"
}

resource "google_iam_workload_identity_pool_provider" "node" {
  for_each = var.nodes

  workload_identity_pool_id          = google_iam_workload_identity_pool.kms_nodes.workload_identity_pool_id
  workload_identity_pool_provider_id = each.key
  display_name                       = each.key

  # Flip to true to revoke this host without deleting anything.
  disabled = false

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  # A host's key only lives in its own provider, so this just stops a host from
  # claiming another host's name in audit logs.
  attribute_condition = "assertion.sub == \"${each.key}\""

  oidc {
    issuer_uri = var.issuer
    jwks_json  = file(each.value)
  }
}

resource "google_kms_key_ring" "kubernetes" {
  name     = "kubernetes"
  location = "us-central1"
}

resource "google_kms_crypto_key" "secrets" {
  name     = "secrets"
  key_ring = google_kms_key_ring.kubernetes.id
}

# One grant for the whole pool. See "Security properties and caveats" for why.
resource "google_kms_crypto_key_iam_member" "kms_nodes" {
  crypto_key_id = google_kms_crypto_key.secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.kms_nodes.name}/*"
}

# Pass each of these to the plugin as --wif-provider.
output "wif_providers" {
  value = { for k, p in google_iam_workload_identity_pool_provider.node : k => p.name }
}

output "key_uri" {
  value = google_kms_crypto_key.secrets.id
}
```

### gcloud

```sh
gcloud iam workload-identity-pools create kms-nodes \
  --location=global --display-name="KMS plugin nodes"

gcloud iam workload-identity-pools providers create-oidc node-1 \
  --location=global \
  --workload-identity-pool=kms-nodes \
  --issuer-uri=https://tpm.example.internal \
  --jwk-json-path=node-1.jwks.json \
  --attribute-mapping=google.subject=assertion.sub \
  --attribute-condition='assertion.sub == "node-1"'

gcloud kms keys add-iam-policy-binding secrets \
  --keyring=kubernetes --location=us-central1 \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
  --member='principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/kms-nodes/*'
```

## 3. Run the plugin

```sh
k8s-cloudkms-plugin \
  --key-uri=projects/my-project/locations/us-central1/keyRings/kubernetes/cryptoKeys/secrets \
  --wif-provider=projects/123456789/locations/global/workloadIdentityPools/kms-nodes/providers/node-1 \
  --jwt-issuer=https://tpm.example.internal \
  --jwt-subject=node-1 \
  --path-to-unix-socket=/var/run/kmsplugin/socket.sock
```

The plugin fetches a token at startup and exits if that fails. So a wrong
JWKS, issuer, audience, or IAM binding shows up immediately, not on the first
encrypt or decrypt.

If you run it as a static pod or container next to `kube-apiserver`, mount
`/dev/tpmrm0` into it and run it as a user or group that can open the device.

### Checking health

Nothing calls the health check automatically; it's there for debugging by
hand. It listens on a unix socket rather than a port, so run it as root on
the node:

```sh
# Plugin answers on its gRPC socket and has encrypt/decrypt permission on the key.
sudo curl --unix-socket /var/run/kmsplugin/healthz.sock http://localhost/healthz

# Also does a real Encrypt/Decrypt round trip through Cloud KMS.
sudo curl --unix-socket /var/run/kmsplugin/healthz.sock 'http://localhost/healthz?ping-kms=true'
```

Either prints `ok` when healthy, or an error with a non-200 status.

### Flags

All upstream flags are supported except `--gce-config` and `--healthz-port`.
This wrapper adds the following:

| Flag | Default | Description |
| --- | --- | --- |
| `--wif-provider` | *(required)* | Provider resource name: `projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROVIDER`. |
| `--jwt-issuer` | *(required)* | `iss` claim. Must match the provider's issuer URI. |
| `--jwt-subject` | hostname | `sub` claim. Mapped to `google.subject`. |
| `--jwt-lifetime` | `5m` | Lifetime of each TPM-signed JWT, at most `1h`. It is only used for the STS exchange. |
| `--path-to-tpm` | `/dev/tpmrm0` | TPM resource manager device. |
| `--tpm-key-handle` | `0x81010101` | Persistent handle of the key created by `tpm-wif-key`. |
| `--healthz-socket` | `/var/run/kmsplugin/healthz.sock` | Unix socket for healthz, replacing upstream's TCP port. Each request makes Cloud KMS calls as this node, so it isn't exposed on the network or to other local users. See [Checking health](#checking-health). |
| `--impersonate-service-account` | *(none)* | Optional service account email to impersonate. If empty, the pool identity is used directly, as in the IAM examples above. |

The JWT's `aud` is the provider's default allowed audience,
`https://iam.googleapis.com/<wif-provider>`, so don't set `allowed_audiences`
on the provider.

## Revoking a host

Do any one of these. Each blocks new token exchanges immediately. Tokens that
were already issued expire within an hour.

- **Disable the provider** (reversible): set `disabled = true` in Terraform,
  or run
  `gcloud iam workload-identity-pools providers update-oidc node-1 --location=global --workload-identity-pool=kms-nodes --disabled`.
- **Delete the provider**: remove the host from `var.nodes`, or run
  `gcloud iam workload-identity-pools providers delete …`.
- **Replace its JWKS** with one that no longer contains the host's key (only
  relevant if several hosts share a provider).

## Rotating a host's key

Provision a new key at a different handle, append it to the host's JWKS (up to
8 keys), and point `--tpm-key-handle` at it. Then remove the old key from the
JWKS. To delete the old key from the TPM itself, run
`tpm2_evictcontrol -C o -c 0x81010101` (from tpm2-tools).

## Keeping up with upstream

`cmd/k8s-cloudkms-plugin/main.go` is a copy of upstream's `main`. Only the
HTTP client construction and the TPM/WIF flags differ. When you bump the
upstream module, diff its `cmd/k8s-cloudkms-plugin/main.go` against this one
and carry over any changes.
