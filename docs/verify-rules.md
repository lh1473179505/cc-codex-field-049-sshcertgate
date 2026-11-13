# Verify rules

Reuse `parse_cert_file` / `parse_authorized_keys_line` from `sshcertgate.parse`. Do not reimplement the wire format, and do not call `ssh-keygen`, `ssh`, or an external CA.

`inspect` only shows what the parser saw. `verify` has to decide whether this certificate may be accepted *for a specific login attempt*: a principal, a certificate kind (`user` or `host`), an optional source address, an optional command, and a clock (`--now`, Unix seconds).

## Trust store

`--trust` is a JSON object:

- `cas`: a list of CA entries. Each entry has:
  - `name`: a short identifier used in the report's `matched_ca` field.
  - `pubkey`: an `ssh-ed25519` public key line (the same format as `*.pub`).
  - `allowed_cert_types`: a list containing `"user"`, `"host"`, or both. A CA may only issue the kinds listed here.
  - `allowed_principals`: either `null` (no extra restriction) or a list of principal names. If it is a list, every principal *in the certificate* must be a member of that list. A certificate that contains some other principal is `ca_principal_not_allowed` even if the login principal itself would have been allowed.
  - `max_ttl_seconds`: the maximum permitted value of `valid_before - valid_after`. A certificate whose window is longer is `ttl_exceeds_ca`.
- `revoked_serials`: a list of integer serial numbers. A match is `revoked`.

A CA matches the certificate when the CA public key bytes (the key blob, not the comment) equal the certificate's signature key. If no trusted CA matches, the decision is `deny` with `untrusted_ca`. Do not fall back to the leaf key to verify the signature.

## When to allow

A login is only `allow` when all of the following hold:

1. The certificate parses successfully (`ok` is true). If the parser returns an error, use `parse_error` and include the parser's `error` string as well if you want a more specific code; `parse_error` must be present.
2. There is no trailing leftover. `trailing > 0` (a second line after the key, or extra bytes after the signature blob) is `trailing_garbage`.
3. The signature over `cert.signed_bytes` verifies with the matched CA's ed25519 public key. The signature algorithm in the cert must be `ssh-ed25519`. Failure is `bad_signature`.
4. The matched CA is allowed to issue this certificate kind (`ca_type_mismatch` otherwise).
5. `--cert-type` equals the certificate's own kind (`cert_type_mismatch` otherwise).
6. `--now >= valid_after` and `--now < valid_before`. Too early is `not_yet_valid`; too late is `expired`. The valid-before instant itself is already expired.
7. The certificate's validity window does not exceed the CA's `max_ttl_seconds` (`ttl_exceeds_ca`).
8. The serial is not in `revoked_serials` (`revoked`).
9. The certificate has a non-empty principal list, and `--principal` is an exact string match for one of them. An empty list is `empty_principals` (this lab does not treat an empty list as a wildcard). A miss is `principal_mismatch`.
10. Critical options are handled as follows. Unknown option names are `unknown_critical_option`. Known names in this lab are only `force-command` and `source-address`.
    - `source-address`: the value is a comma-separated list of IPv4 or IPv6 CIDR prefixes (spaces after commas are allowed). `--source-address` must be a single IP that falls inside at least one prefix (`source_address_mismatch`). If the option is present and `--source-address` was omitted, that is `source_address_missing`. If the option is absent, any address (including omitted) is fine.
    - `force-command`: `--command` must be exactly equal to the option value (`force_command_mismatch`). If the option is present and `--command` was omitted, that is `force_command_missing`. If the option is absent, any command (including omitted) is fine.
11. Extensions are not critical. They may be copied into the report but they do not affect the decision.

Several reason codes may apply at once. When more than one condition matches, list them in this order, unique, and stop only after collecting every code that the rules above define for the input (do not hide `revoked` just because the clock is also expired):

`parse_error`, `trailing_garbage`, `bad_signature`, `untrusted_ca`, `ca_type_mismatch`, `cert_type_mismatch`, `not_yet_valid`, `expired`, `ttl_exceeds_ca`, `revoked`, `empty_principals`, `principal_mismatch`, `ca_principal_not_allowed`, `source_address_missing`, `source_address_mismatch`, `force_command_missing`, `force_command_mismatch`, `unknown_critical_option`.

If the certificate does not parse, do not invent values for the other checks; report `parse_error` (and `trailing_garbage` if you can still see leftover bytes on the line). If it parses but the signature is bad or the CA is untrusted, still run the remaining policy checks against the parsed fields — a revoked, expired, untrusted cert should carry every matching code.

## Report

See `docs/report-schema.md`. `matched_ca` is the `name` of the matching trust entry on a successful key match, even when the login is later denied; it is `null` when no CA key matches.

## Exit codes

- `allow` → exit 0
- `deny` → exit 1
- unreadable input, unreadable trust store, or an implementation error that prevents a report → exit 2. If you can still write a deny report, prefer that and exit 1.

## Public fixtures

Run these with a trust store at `fixtures/trust/ca-trust.json` and `--now 1763000000` unless a row says otherwise:

- `fixtures/certs/ok-user.pub` → allow for `--principal alice --cert-type user --source-address 10.8.1.20` (no command)
- `fixtures/certs/ok-user-force.pub` → allow for `--principal alice --cert-type user --source-address 10.8.1.20 --command /usr/bin/backup`
- `fixtures/certs/expired.pub` → deny, reason includes `expired`, principal alice, user, `--now 1763000000`
- `fixtures/certs/not-yet.pub` → deny, reason includes `not_yet_valid`
- `fixtures/certs/wrong-principal.pub` → deny, reason includes `principal_mismatch` when principal is `alice`
- `fixtures/certs/revoked.pub` → deny, reason includes `revoked`
- `fixtures/certs/bad-signature.pub` → deny, reason includes `bad_signature`
- `fixtures/certs/src-miss.pub` → deny, reason includes `source_address_mismatch` when `--source-address 198.51.100.9`
- `fixtures/certs/unknown-crit.pub` → deny, reason includes `unknown_critical_option`
- `fixtures/certs/host-as-user.pub` → deny, reason includes `cert_type_mismatch` when `--cert-type user --principal bastion`
