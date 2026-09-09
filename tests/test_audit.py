from __future__ import annotations

import base64
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from floppy_audit.audit import audit_export, render_html

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.did = "did:key:z" + base58(b"\xed\x01" + public)

    def record(
        self,
        text: str = "hello",
        nonce: int = 9_223_372_036_854_775_807,
    ) -> dict:
        payload = f"lobby|{nonce}|{text}".encode()
        signature = (
            base64.urlsafe_b64encode(self.key.sign(payload)).decode().rstrip("=")
        )
        return {
            "seq": 42,
            "ts": "2026-01-01T00:00:00Z",
            "from": self.did,
            "text": text,
            "nonce": nonce,
            "sig": signature,
        }

    def test_verifies_19_digit_nonce_without_rounding(self) -> None:
        raw = (json.dumps(self.record(), separators=(",", ":")) + "\n").encode()
        report = audit_export(raw, "lobby", self.did)
        self.assertEqual(
            report["target"], {"records": 1, "valid": 1, "invalid": 0}
        )
        self.assertEqual(report["records"][0]["nonce"], "9223372036854775807")

    def test_detects_modified_message(self) -> None:
        record = self.record()
        record["text"] = "tampered"
        report = audit_export((json.dumps(record) + "\n").encode(), "lobby", self.did)
        self.assertEqual(report["target"]["invalid"], 1)

    def test_counts_unsigned_and_malformed_records(self) -> None:
        unsigned = {"seq": 1, "from": "alice", "text": "hi"}
        raw = json.dumps(unsigned).encode() + b"\nnot-json\n"
        report = audit_export(raw, "lobby", self.did)
        self.assertEqual(report["counts"]["unsigned"], 1)
        self.assertEqual(report["counts"]["malformed"], 1)

    def test_html_escapes_untrusted_message_text(self) -> None:
        raw = (json.dumps(self.record("<script>alert(1)</script>")) + "\n").encode()
        rendered = render_html(audit_export(raw, "lobby", self.did))
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
