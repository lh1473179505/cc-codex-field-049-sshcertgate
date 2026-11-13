# Certificate format

This lab only accepts the OpenSSH `ssh-ed25519-cert-v01@openssh.com` authorized_keys line (type, base64 blob, optional comment, a single trailing newline).

The signed region is already isolated by the parser as `signed_bytes`: it starts at the cert-type string and runs through the CA signature key, exclusive of the trailing signature string. The signature blob itself is `string "ssh-ed25519" || string <64-byte raw signature>`.

Critical options and extensions are name/value pairs. For `force-command` and `source-address` the value is the inner decoded string (a command, or comma-separated CIDRs). Extensions such as `permit-pty` typically have an empty value and are not critical.

The parser also exposes `ca_key_b64` (the raw signature-key blob, base64) and `leaf_key_b64` (the 32-byte ed25519 public key, base64). Trust-store `pubkey` lines are ordinary `ssh-ed25519` public keys; match them by key bytes, not by comment text.
