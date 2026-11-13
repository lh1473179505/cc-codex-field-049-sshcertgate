# Report schema

`verify` writes a JSON object to `--report` with these keys:

- `decision`: `allow` or `deny`.
- `reason_codes`: array of strings, unique, in the order given by the rules. Empty on allow.
- `matched_ca`: the trust-store `name` of the CA whose public key equals the certificate's signature key, or `null`.
- `cert`: the object produced by `Cert.as_dict()` on the parsed certificate (the same shape `inspect` prints).
- `principal`, `cert_type`, `source_address`, `command`, `now`: the login attempt, copied from the CLI (`source_address` and `command` may be `null`).

Unknown keys are ignored by the CLI. Do not omit the keys above.
