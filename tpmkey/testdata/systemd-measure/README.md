# systemd-measure fixture

Real output of systemd 257's `systemd-measure`, used to check that tpmkey
accepts PCR policies exactly as systemd/ukify sign them. The section files are
dummy contents standing in for a UKI's `.linux`, `.osrel`, `.cmdline` and
`.initrd`.

Regenerate (the private key is throwaway and deliberately not kept):

```sh
openssl genrsa -out pcr-private-key.pem 2048
openssl rsa -in pcr-private-key.pem -pubout -out pcr-public-key.pem
/usr/lib/systemd/systemd-measure sign \
  --linux=linux --osrel=osrel --cmdline=cmdline --initrd=initrd \
  --bank=sha256 \
  --phase=enter-initrd:leave-initrd:sysinit:ready --phase=sysinit:ready \
  --private-key=pcr-private-key.pem --public-key=pcr-public-key.pem \
  --json=pretty > tpm2-pcr-signature.json
rm pcr-private-key.pem
```

`systemd-measure sign` needs the tpm2-tss libraries (`libtss2-esys`,
`libtss2-mu`, `libtss2-rc`) installed.
