"""Unit tests for projet_rsa.py: normal paths and every expected refusal."""
import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import projet_rsa as pr

PASSWORD = b"test-password"


def flip_first_byte(envelope: dict, field: str) -> dict:
    tampered = dict(envelope)
    raw = bytearray(base64.b64decode(tampered[field]))
    raw[0] ^= 1
    tampered[field] = base64.b64encode(bytes(raw)).decode()
    return tampered


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = pr.generate_keys(2048)
        cls.bob = pr.generate_keys(2048)
        cls.eve = pr.generate_keys(2048)
        cls.bob3072 = pr.generate_keys(3072)

    # -- normal paths ------------------------------------------------------
    def test_rsa_unicode_roundtrip(self):
        text = "Salut Bob ! Ça marche : 你好 🔐".encode("utf-8")
        env = pr.encrypt_message(text, self.bob.public_key(), "rsa", self.alice)
        self.assertEqual(pr.decrypt_message(env, self.bob, self.alice.public_key()), text)

    def test_hybrid_one_mebibyte_binary(self):
        blob = os.urandom(1024 * 1024)
        env = pr.encrypt_message(blob, self.bob.public_key(), "hybrid", self.alice)
        self.assertEqual(pr.decrypt_message(env, self.bob, self.alice.public_key()), blob)

    def test_oaep_limit_2048_accepts_190_bytes(self):
        env = pr.encrypt_message(b"a" * 190, self.bob.public_key(), "rsa", self.alice)
        self.assertEqual(len(pr.decrypt_message(env, self.bob, self.alice.public_key())), 190)

    def test_oaep_limit_2048_refuses_191_bytes(self):
        with self.assertRaises(pr.CryptoError):
            pr.encrypt_message(b"a" * 191, self.bob.public_key(), "rsa", self.alice)

    def test_oaep_limit_3072_accepts_318_refuses_319(self):
        self.assertEqual(pr.oaep_max_bytes(self.bob3072.public_key()), 318)
        pr.encrypt_message(b"a" * 318, self.bob3072.public_key(), "rsa", self.alice)
        with self.assertRaises(pr.CryptoError):
            pr.encrypt_message(b"a" * 319, self.bob3072.public_key(), "rsa", self.alice)

    def test_hybrid_refuses_more_than_8_mib(self):
        with self.assertRaises(pr.CryptoError):
            pr.encrypt_message(b"\0" * (pr.MAX_SOURCE_BYTES + 1), self.bob.public_key(), "hybrid")

    # -- refusals ------------------------------------------------------------
    def test_wrong_recipient_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", self.alice)
        with self.assertRaises(pr.CryptoError):
            pr.decrypt_message(env, self.eve, self.alice.public_key())

    def test_sender_key_substitution_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "hybrid", self.eve)
        with self.assertRaises(pr.CryptoError):
            pr.decrypt_message(env, self.bob, self.alice.public_key())

    def test_altered_ciphertext_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "hybrid", self.alice)
        with self.assertRaises(pr.CryptoError):
            pr.decrypt_message(flip_first_byte(env, "ciphertext"), self.bob, self.alice.public_key())

    def test_altered_signature_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", self.alice)
        with self.assertRaises(pr.CryptoError):
            pr.decrypt_message(flip_first_byte(env, "signature"), self.bob, self.alice.public_key())

    def test_altered_gcm_tag_rejected_on_unsigned_envelope(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "hybrid", None)
        tampered = dict(env)
        raw = bytearray(base64.b64decode(env["ciphertext"]))
        raw[-1] ^= 1  # the GCM tag is the last 16 bytes
        tampered["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaisesRegex(pr.CryptoError, "AES-GCM"):
            pr.decrypt_message(tampered, self.bob, allow_unsigned=True)

    def test_unsigned_refused_by_default(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", None)
        with self.assertRaises(pr.CryptoError):
            pr.decrypt_message(env, self.bob)

    def test_unknown_mode_and_version_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", self.alice)
        for field, value in (("mode", "aes"), ("version", 99)):
            with self.subTest(field=field), self.assertRaises(pr.CryptoError):
                pr.validate_envelope({**env, field: value})

    def test_extra_or_missing_field_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", self.alice)
        with self.assertRaises(pr.CryptoError):
            pr.validate_envelope({**env, "extra": "x"})
        missing = dict(env)
        del missing["recipient"]
        with self.assertRaises(pr.CryptoError):
            pr.validate_envelope(missing)

    def test_duplicate_json_keys_rejected(self):
        raw = b'{"version": 1, "version": 1, "mode": "rsa"}'
        with self.assertRaisesRegex(pr.CryptoError, "duplicate"):
            pr.parse_envelope(raw)

    def test_invalid_base64_rejected(self):
        env = pr.encrypt_message(b"hello", self.bob.public_key(), "rsa", None)
        env["ciphertext"] = "@@not-base64@@"
        with self.assertRaisesRegex(pr.CryptoError, "Base64"):
            pr.decrypt_message(env, self.bob, allow_unsigned=True)


class KeyStorageTests(unittest.TestCase):
    def test_protected_pem_needs_the_right_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv, pub = pr.save_key_pair(pr.generate_keys(2048), Path(tmp), "alice", PASSWORD)
            self.assertIn(b"ENCRYPTED PRIVATE KEY", priv.read_bytes())
            pr.load_private(priv, PASSWORD)
            with self.assertRaises(pr.CryptoError):
                pr.load_private(priv, b"wrong-password")
            self.assertEqual(len(pr.fingerprint(pr.load_public(pub))), 64)

    def test_existing_key_files_are_not_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            pr.save_key_pair(pr.generate_keys(2048), Path(tmp), "bob", PASSWORD)
            with self.assertRaises(pr.CryptoError):
                pr.save_key_pair(pr.generate_keys(2048), Path(tmp), "bob", PASSWORD)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = pr.main(list(argv), password_source=lambda *a, **k: PASSWORD)
        return code, out.getvalue(), err.getvalue()

    def test_cli_full_signed_exchange(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            self.assertEqual(self.run_cli("keygen", "--name", "alice", "--out-dir", tmp)[0], 0)
            self.assertEqual(self.run_cli("keygen", "--name", "bob", "--out-dir", tmp)[0], 0)
            code, _, _ = self.run_cli("encrypt", "--to", str(t / "bob_public.pem"),
                                      "--from", str(t / "alice_private.pem"),
                                      "--message", "Bonjour Bob", "--out", str(t / "msg.json"))
            self.assertEqual(code, 0)
            code, _, _ = self.run_cli("decrypt", "--key", str(t / "bob_private.pem"),
                                      "--sender", str(t / "alice_public.pem"),
                                      "--in", str(t / "msg.json"), "--out", str(t / "clear.txt"))
            self.assertEqual(code, 0)
            self.assertEqual((t / "clear.txt").read_text(encoding="utf-8"), "Bonjour Bob")
            # an existing output file is refused
            code, _, err = self.run_cli("decrypt", "--key", str(t / "bob_private.pem"),
                                        "--sender", str(t / "alice_public.pem"),
                                        "--in", str(t / "msg.json"), "--out", str(t / "clear.txt"))
            self.assertEqual(code, 1)
            self.assertIn("overwrite", err)

    def test_cli_failure_writes_no_plaintext_and_bad_syntax_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            for name in ("alice", "bob", "eve"):
                self.run_cli("keygen", "--name", name, "--out-dir", tmp)
            self.run_cli("encrypt", "--to", str(t / "bob_public.pem"), "--from",
                         str(t / "alice_private.pem"), "--message", "secret",
                         "--out", str(t / "msg.json"))
            code, _, _ = self.run_cli("decrypt", "--key", str(t / "bob_private.pem"),
                                      "--sender", str(t / "eve_public.pem"),
                                      "--in", str(t / "msg.json"), "--out", str(t / "clear.txt"))
            self.assertEqual(code, 1)
            self.assertFalse((t / "clear.txt").exists())
            with self.assertRaises(SystemExit) as ctx, redirect_stderr(io.StringIO()):
                pr.main(["encrypt", "--mode", "nope"])
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
