"""Download, parse, and verify raw Technocore room exports."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_INDEX = {character: index for index, character in enumerate(ALPHABET)}
ED25519_MULTICODEC = b"\xed\x01"
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}")
MAX_EXPORT_BYTES = 16 * 1024 * 1024


class AuditError(RuntimeError):
    """An export could not be downloaded or audited safely."""


def _decode_base58(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = ALPHABET_INDEX[character]
        except KeyError as error:
            raise AuditError(f"invalid base58 character {character!r}") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    prefix = "did:key:z"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise AuditError("DID must be an Ed25519 did:key:z6Mk identifier")
    multibase = did[len("did:key:") :]
    if len(multibase) != 48 or not multibase.startswith("z6Mk"):
        raise AuditError("DID is not a canonical Ed25519 did:key")
    decoded = _decode_base58(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(ED25519_MULTICODEC):
        raise AuditError("DID does not contain an Ed25519 public key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise AuditError("DID contains an invalid Ed25519 public key") from error


def _nonce_digits(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AuditError("nonce is not an integer or decimal string")
    nonce = str(value)
    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise AuditError("nonce must contain 1-19 decimal digits")
    return nonce


def verify_record(room: str, record: dict[str, Any]) -> tuple[str, str]:
    """Return a status and detail for one decoded room record."""
    sender = record.get("from")
    if not isinstance(sender, str) or not sender.startswith("did:key:"):
        return "unsigned", "No verifiable DID signature"
    try:
        text = record.get("text")
        signature = record.get("sig")
        if not isinstance(text, str):
            raise AuditError("text is not a string")
        if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
            raise AuditError("signature is not canonical unpadded base64url")
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        if len(raw_signature) != 64:
            raise AuditError("signature is not 64 bytes")
        canonical_signature = base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
        if canonical_signature != signature:
            raise AuditError("signature encoding is not canonical")
        nonce = _nonce_digits(record.get("nonce"))
        payload = f"{room}|{nonce}|{text}".encode("utf-8")
        public_key_from_did(sender).verify(raw_signature, payload)
    except InvalidSignature:
        return "invalid", "Signature does not match the DID and stored payload"
    except (AuditError, ValueError) as error:
        return "invalid", str(error)
    return "valid", "Ed25519 signature verified"


def audit_export(raw_export: bytes, room: str, target_did: str) -> dict[str, Any]:
    if NAME_PATTERN.fullmatch(room) is None:
        raise AuditError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    public_key_from_did(target_did)
    counts = {
        "records": 0,
        "target_valid": 0,
        "target_invalid": 0,
        "signed_other": 0,
        "unsigned": 0,
        "malformed": 0,
    }
    selected: list[dict[str, Any]] = []

    for line_number, raw_line in enumerate(raw_export.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            counts["malformed"] += 1
            continue
        if not isinstance(record, dict):
            counts["malformed"] += 1
            continue
        counts["records"] += 1
        sender = record.get("from")
        if sender == target_did:
            status, detail = verify_record(room, record)
            counts[f"target_{status}"] += 1
            selected.append(
                {
                    "line": line_number,
                    "seq": record.get("seq"),
                    "ts": record.get("ts"),
                    "from": target_did,
                    "text": record.get("text"),
                    "nonce": str(record.get("nonce")),
                    "sig": record.get("sig"),
                    "verification": status,
                    "detail": detail,
                    "raw_line_sha256": hashlib.sha256(raw_line).hexdigest(),
                }
            )
        elif isinstance(sender, str) and sender.startswith("did:key:"):
            counts["signed_other"] += 1
        else:
            counts["unsigned"] += 1

    return {
        "schema": "floppy-technocore-audit-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "room": room,
        "target_did": target_did,
        "export_sha256": hashlib.sha256(raw_export).hexdigest(),
        "counts": counts,
        "target": {
            "records": len(selected),
            "valid": sum(item["verification"] == "valid" for item in selected),
            "invalid": sum(item["verification"] == "invalid" for item in selected),
        },
        "records": selected,
        "notes": [
            "The signature covers room|nonce|text as UTF-8.",
            "Sequence and timestamp are assigned by the server and are not signed.",
            "Signed content proves control of a DID key, not identity or truthfulness.",
        ],
    }


def _validated_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    parsed = urlsplit(normalized)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise AuditError("base URL must use HTTPS, except for a loopback test server")
    if not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AuditError("base URL must contain a host and no credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise AuditError("base URL must not contain a path")
    return normalized


def download_export(room: str, base_url: str, timeout: float) -> tuple[bytes, str | None]:
    if NAME_PATTERN.fullmatch(room) is None:
        raise AuditError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    if timeout <= 0:
        raise AuditError("timeout must be greater than zero")
    url = f"{_validated_base_url(base_url)}/r/{room}/export"
    request = Request(
        url,
        headers={"Accept": "application/x-ndjson", "User-Agent": "floppy-audit/0.1.0"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            generation = response.headers.get("X-Room-Generation")
            body = response.read(MAX_EXPORT_BYTES + 1)
    except HTTPError as error:
        raise AuditError(f"Technocore returned HTTP {error.code}") from None
    except (URLError, TimeoutError, OSError) as error:
        raise AuditError(f"could not download room export: {error}") from error
    if len(body) > MAX_EXPORT_BYTES:
        raise AuditError(f"room export exceeds {MAX_EXPORT_BYTES} bytes")
    return body, generation


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def render_html(report: dict[str, Any]) -> str:
    escape = lambda value: html.escape(str(value), quote=True)
    rows = []
    for record in report["records"]:
        status = escape(record["verification"])
        rows.append(
            "<tr>"
            f"<td>{escape(record['seq'])}</td>"
            f"<td>{escape(record['ts'])}</td>"
            f"<td><span class=\"status {status}\">{status}</span></td>"
            f"<td><code>{escape(record['nonce'])}</code></td>"
            f"<td class=\"message\">{escape(record['text'])}</td>"
            "</tr>"
        )
    table_body = "".join(rows) or '<tr><td colspan="5">No records found for this DID.</td></tr>'
    target = report["target"]
    counts = report["counts"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Floppy Audit — {escape(report['room'])}</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:3rem auto;padding:0 1rem;color:#18212b}}
code{{overflow-wrap:anywhere}} table{{border-collapse:collapse;width:100%;margin-top:1.5rem}}
th,td{{border:1px solid #ccd4dc;padding:.55rem;text-align:left;vertical-align:top}}
th{{background:#eef2f5}} .message{{white-space:pre-wrap;overflow-wrap:anywhere}}
.status{{font-weight:700}} .valid{{color:#087830}} .invalid{{color:#b42318}} .unsigned{{color:#6b7280}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}} .card{{border:1px solid #ccd4dc;border-radius:.5rem;padding:.75rem 1rem}}
</style>
</head>
<body>
<h1>Floppy Technocore Audit</h1>
<p>Room <code>{escape(report['room'])}</code> · DID <code>{escape(report['target_did'])}</code></p>
<div class="cards">
<div class="card"><strong>{target['valid']}</strong> valid target records</div>
<div class="card"><strong>{target['invalid']}</strong> invalid target records</div>
<div class="card"><strong>{counts['records']}</strong> export records audited</div>
</div>
<p>Export SHA-256: <code>{escape(report['export_sha256'])}</code></p>
<table><thead><tr><th>Sequence</th><th>Timestamp</th><th>Signature</th><th>Nonce</th><th>Stored text</th></tr></thead>
<tbody>{table_body}</tbody></table>
<p>Signatures cover <code>room|nonce|text</code>. Sequence and timestamp are server-assigned and are not signed.</p>
</body></html>"""
