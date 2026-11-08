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
  has no password. You can optionally
  [bind it to boot state](#binding-the-key-to-boot-state-pcr-7-and-pcr-11).
  That limits *which boots* can use it, but not who can use it on a correctly
  booted host.
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
  VERSION="v1.0.1"
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

To bind the key to boot state, add `-pcrs` and/or `-pcr-public-key` to
`create`. See
[Binding the key to boot state](#binding-the-key-to-boot-state-pcr-7-and-pcr-11).
The binding can't be added to an existing key.

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
| `--tpm-key-pcrs` | *(none)* | PCRs the key is bound to at fixed values, as given to `tpm-wif-key create -pcrs` (for example `7`). Must match the key. |
| `--tpm-pcr-public-key` | *(none)* | PEM RSA public key (or certificate) the key accepts signed PCR policies from, as given to `tpm-wif-key create -pcr-public-key`. Must match the key. |
| `--tpm-pcr-signature` | `/run/systemd/tpm2-pcr-signature.json` | Signed PCR policies for the booted UKI. Only used with `--tpm-pcr-public-key`. Read on every signature. |
| `--healthz-socket` | `/var/run/kmsplugin/healthz.sock` | Unix socket for healthz, replacing upstream's TCP port. Each request makes Cloud KMS calls as this node, so it isn't exposed on the network or to other local users. See [Checking health](#checking-health). |
| `--impersonate-service-account` | *(none)* | Optional service account email to impersonate. If empty, the pool identity is used directly, as in the IAM examples above. |

The JWT's `aud` is the provider's default allowed audience,
`https://iam.googleapis.com/<wif-provider>`, so don't set `allowed_audiences`
on the provider.

## Binding the key to boot state (PCR 7 and PCR 11)

By default, anything that can open `/dev/tpmrm0` can use the key, whatever
the machine booted. With a PCR binding, the TPM only lets the key sign when
the boot measurements match. So someone who boots the machine into something
else can't use the key, for example after stealing it, or at the console.

The binding is fixed when the key is created. It doesn't stop root on a
correctly booted host, and it doesn't defend against a hardware interposer on
a discrete TPM.

There are two ways to bind the key. You can use either one, or both.

| | `-pcrs 7` (fixed values) | `-pcr-public-key` (signed PCR 11 policies) |
| --- | --- | --- |
| Binds to | The values the PCRs held when the key was created. | Any PCR 11 value whose policy you signed, using TPM2_PolicyAuthorize. |
| Kernel update | Nothing to do (PCR 7 doesn't change). | Nothing to do on the key. Your UKI build signs the new UKI's PCR 11. |
| Needs a new key when | Secure Boot state changes: db/dbx/KEK/PK updates, firmware updates, toggling Secure Boot, a changed shim SBAT level. | You rotate the PCR-signing key. |

### PCR 7: Secure Boot state

PCR 7 records the Secure Boot configuration (the `SecureBoot`, `PK`, `KEK`,
`db` and `dbx` variables) and which certificate authorised each part of the
boot chain. It records *which signer* booted the machine, not which binaries
ran.

- **On a stock Microsoft/distribution Secure Boot setup, this is weak.** It
  stops boots with Secure Boot off and boots with foreign keys enrolled. But a
  live USB of the same distribution, an edited kernel command line, or any
  other kernel from that vendor gives an identical PCR 7, and a root shell.
- **With your own db that only trusts your signing key, it's strong.** Only
  something you signed can use the key. Anything you have ever signed still
  counts, including old UKIs and EFI tools, until you revoke it in dbx or
  rotate the db key.

The key has to be re-created when PCR 7 changes (see
[When PCR 7 changes](#when-pcr-7-changes)). Plan for firmware and dbx updates,
and for the Microsoft UEFI CA 2023 rollover if your db includes Microsoft's
keys.

### PCR 11: unified kernel image, with signed policies

systemd-stub measures every section of the unified kernel image (UKI) it
boots into PCR 11: kernel, initrd, command line, os-release and so on.
`systemd-pcrphase` then measures the boot phases (`enter-initrd`,
`leave-initrd`, `sysinit`, `ready`, and later `shutdown`). Because PCR 11
changes with every kernel, the key isn't bound to its value. It is bound to a
**PCR-signing key**. At build time, ukify signs the PCR 11 value each UKI will
produce. At boot, systemd puts those signatures in
`/run/systemd/tpm2-pcr-signature.json`, and the plugin presents the one that
matches the current PCR 11. The TPM checks the signature against the key that
was fixed when the WIF key was created.

Requirements, and what to know:

- **PCR 11 is only meaningful if Secure Boot boots nothing but your
  systemd-stub UKIs.** Anything else that Secure Boot accepts leaves PCR 11
  alone. That includes a GRUB chain, a bare kernel in a systemd-boot Type #1
  entry, or a signed EFI shell. On such a boot, root can extend PCR 11 by hand
  to the exact "ready" value, because every measured input is public. Use
  your own db (see PCR 7), make sure only UKIs and the boot loader carry its
  signature, and bind PCR 7 too.
- **Use a dedicated PCR-signing key, and sign only the fully booted phase.**
  Every policy the key ever signed stays valid forever, because there is no
  rollback protection. ukify signs initrd phases by default, which would make
  the WIF key usable from the initrd. Keep this key separate from any key you
  use for `systemd-cryptenroll`, which needs the initrd phases.
- **Signatures are RSA, PCR bank SHA-256.** That's what systemd produces.

#### 1. Create a PCR-signing key and sign your UKIs

```sh
openssl genrsa -out /etc/kernel/kms-plugin-pcr.key 2048
openssl rsa -in /etc/kernel/kms-plugin-pcr.key -pubout -out /etc/kernel/kms-plugin-pcr.pub.pem
install -D -m 0644 /etc/kernel/kms-plugin-pcr.pub.pem /etc/k8s-cloudkms-plugin/pcr-public-key.pem
```

Add this key to your `ukify build` invocation (or the `[PCRSignature:…]`
section of `ukify.conf`), alongside your existing options:

```sh
ukify build … \
  --pcr-banks=sha256 \
  --pcr-private-key=/etc/kernel/kms-plugin-pcr.key \
  --pcr-public-key=/etc/kernel/kms-plugin-pcr.pub.pem \
  --phases=enter-initrd:leave-initrd:sysinit:ready
```

If you already pass a PCR key to ukify (for example for
`systemd-cryptenroll --tpm2-public-key`), add this one as another
`--pcr-private-key`/`--pcr-public-key` pair. The plugin finds its signatures
by the key's fingerprint, so the keys can share the signature file. Two
things change with a second key:

- **ukify needs a `--phases` for every key** once you give one to any of them.
- **ukify stops embedding a `.pcrpkey` section** unless you pass
  `--pcrpkey=` explicitly. If anything relies on
  `/run/systemd/tpm2-pcr-public-key.pem`, as `systemd-cryptenroll` does by
  default, pass `--pcrpkey=` with that key's public key.

Reboot into a UKI built this way and check what's measured:

- `/run/systemd/tpm2-pcr-signature.json` should exist.
- `journalctl -b -u systemd-pcrphase-initrd.service` should show
  `enter-initrd` and `leave-initrd`.
  - If it doesn't, the initrd doesn't run `systemd-pcrphase`. Use
    `--phases=sysinit:ready` instead.
- If the signature file is missing, the initrd didn't copy it. Install it from
  the UKI's `.pcrsig` section as part of your UKI build, and point
  `--tpm-pcr-signature` at it:

  ```sh
  objcopy -O binary --only-section=.pcrsig uki.efi /etc/k8s-cloudkms-plugin/tpm2-pcr-signature.json
  ```

#### 2. Create the key

For a signed PCR 11 policy plus PCR 7 at its current value, run on the host,
booted normally into your signed UKI:

```sh
sudo tpm-wif-key create \
  -pcrs 7 \
  -pcr-public-key /etc/k8s-cloudkms-plugin/pcr-public-key.pem \
  > node-1.jwks.json
```

`create` prints what it bound the key to on stderr. It refuses to bind a PCR
that still holds its reset value (all zeros or all `0xff`), because a PCR
nothing measured into matches any boot that also leaves it alone. With
`-pcr-public-key`, it also refuses unless `-pcr-signature` (default
`/run/systemd/tpm2-pcr-signature.json`) has a policy signed by that key that
matches the current boot, so a wrong key or an unsigned UKI fails before
anything is persisted.

For PCR 7 only, drop `-pcr-public-key`. For a signed PCR 11 policy only, drop
`-pcrs 7`. That isn't recommended: see the requirements above.

Check that the key is usable in the current boot. This exits non-zero, with
the reason, if it isn't:

```sh
sudo tpm-wif-key check -pcrs 7 -pcr-public-key /etc/k8s-cloudkms-plugin/pcr-public-key.pem
```

#### 3. Configure the plugin

Pass the same policy to the plugin, for example appended to `PLUGIN_ARGS` in
`/etc/k8s-cloudkms-plugin/env`:

```sh
--tpm-key-pcrs=7 --tpm-pcr-public-key=/etc/k8s-cloudkms-plugin/pcr-public-key.pem
```

If you use a signed PCR 11 policy, uncomment
`After=systemd-pcrphase.service` in the
[systemd unit](deploy/systemd/k8s-cloudkms-plugin.service). Before that unit
runs, PCR 11 doesn't hold the "ready" value yet.

At startup the plugin checks that the key is bound to exactly the configured
policy and that the current boot satisfies it. If it isn't, the plugin exits
with the reason, for example that PCR 7 changed, the PCR-signing key differs,
or no signed policy matches this UKI and phase. If the flags are missing for a
bound key, or set for an unbound one, it also refuses to start.

### When PCR 7 changes

After a Secure Boot or firmware change, a PCR 7-bound key can't sign, so the
plugin on that node won't start. Its kube-apiserver can't read or write
Secrets until you replace the key. Do one control-plane node at a time:

1. Before rebooting, run `tpm-wif-key check …` to confirm the key works now.
2. Apply the update and reboot.
3. Create a new key at another handle. Add the new key's JWK to the host's
   JWKS file and apply. Then point `--tpm-key-handle` at the new key (see
   [Rotating a host's key](#rotating-a-hosts-key)).
4. Treat an *unexpected* PCR 7 change as a security event. Find out what
   changed before you re-create the key.

Updates that change PCR 7 often arrive fleet-wide, through `fwupd` dbx updates
or `shim-signed` on stock setups. A rolling reboot after one takes each
control-plane node's KMS down in turn, so gate those updates on control-plane
nodes.

### Other caveats

- **`systemctl soft-reboot` and kexec don't reset PCRs.** Afterwards PCR 11 no
  longer matches any signed policy, so the key can't be used until a full
  reboot.
- **The TPM's dictionary-attack lockout no longer blocks signing.** A bound
  key is only used through its policy, never its password, so failed password
  attempts against it don't lock it out.

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

For a key bound to boot state, create the new key with the same `-pcrs` and
`-pcr-public-key` options and run `tpm-wif-key check` against its handle.

## Keeping up with upstream

`cmd/k8s-cloudkms-plugin/main.go` is a copy of upstream's `main`. Only the
HTTP client construction and the TPM/WIF flags differ. When you bump the
upstream module, diff its `cmd/k8s-cloudkms-plugin/main.go` against this one
and carry over any changes.
