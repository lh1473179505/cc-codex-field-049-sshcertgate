"""CLI. inspect already works; verify is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sshcertgate.parse import parse_cert_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sshcertgate")
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="show the fields of an OpenSSH certificate")
    ins.add_argument("--cert", required=True)

    ver = sub.add_parser("verify", help="decide whether a certificate may be accepted")
    ver.add_argument("--cert", required=True)
    ver.add_argument("--trust", required=True)
    ver.add_argument("--principal", required=True)
    ver.add_argument("--cert-type", required=True, choices=("user", "host"))
    ver.add_argument("--source-address", default=None)
    ver.add_argument("--command", default=None)
    ver.add_argument("--now", required=True, type=int)
    ver.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "inspect":
        cert = parse_cert_file(args.cert)
        print(json.dumps(cert.as_dict(), ensure_ascii=False, indent=2))
        return 0 if cert.ok else 1

    if args.cmd == "verify":
        from sshcertgate.engine import verify

        path = Path(args.cert)
        try:
            cert_text = path.read_bytes()
        except OSError as exc:
            print(f"failed to read certificate: {exc}", file=sys.stderr)
            return 2
        try:
            trust = json.loads(Path(args.trust).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"failed to read trust store: {exc}", file=sys.stderr)
            return 2
        try:
            report = verify(
                cert_text,
                trust,
                principal=args.principal,
                cert_type=args.cert_type,
                source_address=args.source_address,
                command=args.command,
                now=args.now,
            )
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
