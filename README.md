# sshcertgate

A lab tool for deciding whether an OpenSSH user or host certificate should be accepted by a bastion.

`python -m sshcertgate inspect --cert fixtures/certs/ok-user.pub` already prints the parsed fields, the CA key, and the signed region the verifier needs. `verify` is still a stub: it must apply the trust store, validity window, principals, and critical options as described in `docs/verify-rules.md`.

Python 3 standard library plus the `cryptography` package. No Docker, and no shelling out to `ssh-keygen` or `ssh` for the decision.
