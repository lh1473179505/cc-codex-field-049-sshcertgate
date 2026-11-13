"""Parse OpenSSH ed25519 certificates (ssh-ed25519-cert-v01@openssh.com).

The signed region is the cert type string through the CA signature key,
not including the trailing signature blob. inspect uses this parser.
"""

from __future__ import annotations

import base64
import io
import struct
from dataclasses import dataclass, field


CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com"
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2
CERT_TYPE_NAMES = {CERT_TYPE_USER: "user", CERT_TYPE_HOST: "host"}


class ParseError(ValueError):
    pass


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _read_u32(buf: io.BytesIO) -> int:
    b = buf.read(4)
    if len(b) != 4:
        raise ParseError("truncated_u32")
    return struct.unpack(">I", b)[0]


def _read_u64(buf: io.BytesIO) -> int:
    b = buf.read(8)
    if len(b) != 8:
        raise ParseError("truncated_u64")
    return struct.unpack(">Q", b)[0]


def _read_str(buf: io.BytesIO) -> bytes:
    n = _read_u32(buf)
    d = buf.read(n)
    if len(d) != n:
        raise ParseError("truncated_string")
    return d


def _split_ssh_strings(blob: bytes) -> list[bytes]:
    buf = io.BytesIO(blob)
    out: list[bytes] = []
    while buf.tell() < len(blob):
        out.append(_read_str(buf))
    return out


def _parse_options(blob: bytes) -> list[dict[str, str]]:
    opts: list[dict[str, str]] = []
    buf = io.BytesIO(blob)
    while buf.tell() < len(blob):
        name = _read_str(buf).decode("ascii", "replace")
        data = _read_str(buf)
        value = ""
        if data:
            inner = io.BytesIO(data)
            try:
                value_b = _read_str(inner)
                leftover = inner.read()
                if leftover:
                    raise ParseError("option_value_trailing")
                value = value_b.decode("utf-8", "replace")
            except ParseError:
                value = data.decode("utf-8", "replace")
        opts.append({"name": name, "value": value})
    return opts


@dataclass
class Cert:
    ok: bool
    error: str | None = None
    cert_type_name: str | None = None
    cert_type: int | None = None
    serial: int | None = None
    key_id: str | None = None
    principals: list[str] = field(default_factory=list)
    valid_after: int | None = None
    valid_before: int | None = None
    critical_options: list[dict[str, str]] = field(default_factory=list)
    extensions: list[dict[str, str]] = field(default_factory=list)
    signature_algorithm: str | None = None
    ca_algo: str | None = None
    ca_key_b64: str | None = None
    leaf_key_b64: str | None = None
    signed_bytes: bytes | None = None
    signature: bytes | None = None
    trailing: int = 0
    comment: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "error": self.error,
            "cert_type": self.cert_type_name,
            "serial": self.serial,
            "key_id": self.key_id,
            "principals": list(self.principals),
            "valid_after": self.valid_after,
            "valid_before": self.valid_before,
            "critical_options": list(self.critical_options),
            "extensions": list(self.extensions),
            "signature_algorithm": self.signature_algorithm,
            "ca_algo": self.ca_algo,
            "ca_key_b64": self.ca_key_b64,
            "leaf_key_b64": self.leaf_key_b64,
            "trailing": self.trailing,
            "comment": self.comment,
        }


def _fail(code: str) -> Cert:
    return Cert(ok=False, error=code)


def parse_authorized_keys_line(text: str | bytes) -> Cert:
    if isinstance(text, bytes):
        raw = text
    else:
        raw = text.encode("utf-8")
    # Allow a single trailing newline; anything else after the first line is trailing.
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    if b"\n" in raw:
        # Keep the first line and remember leftover bytes after it.
        first, rest = raw.split(b"\n", 1)
        trailing = len(rest) + 1
        raw = first
    else:
        trailing = 0
    parts = raw.split(None, 2)
    if len(parts) < 2:
        return _fail("truncated_line")
    typ, b64 = parts[0].decode("ascii", "replace"), parts[1]
    comment = parts[2].decode("utf-8", "replace") if len(parts) == 3 else ""
    if typ != CERT_TYPE:
        return _fail("unsupported_cert_type")
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        return _fail("bad_base64")
    cert = _parse_blob(blob)
    cert.trailing = trailing
    cert.comment = comment or None
    return cert


def parse_cert_file(path: str | bytes) -> Cert:
    from pathlib import Path

    try:
        data = Path(path).read_bytes()
    except OSError:
        return _fail("unreadable")
    return parse_authorized_keys_line(data)


def _parse_blob(blob: bytes) -> Cert:
    buf = io.BytesIO(blob)
    try:
        typ = _read_str(buf).decode("ascii", "replace")
        if typ != CERT_TYPE:
            return _fail("unsupported_cert_type")
        nonce = _read_str(buf)
        pk = _read_str(buf)
        if len(pk) != 32:
            return _fail("bad_leaf_key")
        serial = _read_u64(buf)
        ctype = _read_u32(buf)
        key_id = _read_str(buf).decode("utf-8", "replace")
        principals_blob = _read_str(buf)
        principals = [p.decode("utf-8", "replace") for p in _split_ssh_strings(principals_blob)]
        valid_after = _read_u64(buf)
        valid_before = _read_u64(buf)
        crit = _parse_options(_read_str(buf))
        exts = _parse_options(_read_str(buf))
        _reserved = _read_str(buf)
        sig_key = _read_str(buf)
        signed_end = buf.tell()
        sig_blob = _read_str(buf)
        leftover = buf.read()
    except ParseError as exc:
        return _fail(str(exc) or "parse_error")

    if leftover:
        # Bytes after the certificate signature are trailing garbage.
        trailing_in_blob = len(leftover)
    else:
        trailing_in_blob = 0

    try:
        sk = io.BytesIO(sig_key)
        ca_algo = _read_str(sk).decode("ascii", "replace")
        ca_raw = _read_str(sk)
        if sk.read():
            return _fail("bad_ca_key")
        sb = io.BytesIO(sig_blob)
        sig_algo = _read_str(sb).decode("ascii", "replace")
        signature = _read_str(sb)
        if sb.read():
            return _fail("bad_signature_blob")
    except ParseError:
        return _fail("bad_signature_blob")

    if ctype not in CERT_TYPE_NAMES:
        return _fail("unknown_cert_kind")

    signed_bytes = blob[:signed_end]
    return Cert(
        ok=True,
        cert_type_name=CERT_TYPE_NAMES[ctype],
        cert_type=ctype,
        serial=serial,
        key_id=key_id,
        principals=principals,
        valid_after=valid_after,
        valid_before=valid_before,
        critical_options=crit,
        extensions=exts,
        signature_algorithm=sig_algo,
        ca_algo=ca_algo,
        ca_key_b64=base64.b64encode(sig_key).decode("ascii"),
        leaf_key_b64=base64.b64encode(pk).decode("ascii"),
        signed_bytes=signed_bytes,
        signature=signature,
        trailing=trailing_in_blob,
    )
