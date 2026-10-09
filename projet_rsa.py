#!/usr/bin/env python3
"""Private messaging between two peers with RSA-OAEP, RSA-PSS and AES-256-GCM.

Commands
--------
keygen       create an RSA key pair (private key encrypted with a password)
fingerprint  print the SHA-256 fingerprint of a public key
encrypt      encrypt (and by default sign) a message or a file into a JSON envelope
decrypt      verify and decrypt an envelope
demo         reproducible Alice/Bob scenario, no manual setup

The cryptographic primitives come from the `cryptography` library; RSA arithmetic
is not re-implemented. Exit codes: 0 success, 1 processing error, 2 bad syntax.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
MODES = ("rsa", "hybrid")
KEY_SIZES = (2048, 3072)
PUBLIC_EXPONENT = 65537
SIGNATURE_ALGORITHM = "RSA-PSS-SHA256"
NO_SIGNATURE = "none"
PSS_SALT_LENGTH = 32
MAX_SOURCE_BYTES = 8 * 1024 * 1024  # 8 MiB: largest message or file accepted
MAX_ENVELOPE_BYTES = 12 * 1024 * 1024  # 12 MiB: largest envelope read from disk
NONCE_BYTES = 12
SESSION_KEY_BYTES = 32  # AES-256

COMMON_FIELDS = ("version", "mode", "recipient", "sender", "signature_algorithm", "ciphertext")
HYBRID_FIELDS = ("wrapped_key", "nonce")
BINARY_FIELDS = ("ciphertext", "wrapped_key", "nonce", "signature")


class CryptoError(Exception):
    """Any failure that must stop processing without writing plaintext."""


# --------------------------------------------------------------------------- keys

def oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None)


def pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT_LENGTH)


def oaep_max_bytes(public_key: rsa.RSAPublicKey) -> int:
    """Largest plaintext for RSA-OAEP-SHA256: k - 2*hLen - 2 (190 B for 2048 bits)."""
    k = (public_key.key_size + 7) // 8
    return k - 2 * hashes.SHA256.digest_size - 2


def generate_keys(bits: int = 2048) -> rsa.RSAPrivateKey:
    if bits not in KEY_SIZES:
        raise CryptoError(f"key size must be one of {KEY_SIZES}")
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=bits)


def private_pem(key: rsa.RSAPrivateKey, password: bytes) -> bytes:
    if not password:
        raise CryptoError("the private key password must not be empty")
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password))


def public_pem(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def write_exclusive(path: Path, data: bytes) -> None:
    """Create a new file; never overwrite an existing one."""
    try:
        with open(path, "xb") as handle:
            handle.write(data)
    except FileExistsError as error:
        raise CryptoError(f"refusing to overwrite existing file: {path}") from error


def read_bounded(path: Path, limit: int) -> bytes:
    size = os.path.getsize(path)
    if size > limit:
        raise CryptoError(f"{path} is {size} bytes, limit is {limit}")
    return Path(path).read_bytes()


def save_key_pair(key: rsa.RSAPrivateKey, directory: Path, name: str, password: bytes) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = directory / f"{name}_private.pem", directory / f"{name}_public.pem"
    for path in (priv_path, pub_path):
        if path.exists():
            raise CryptoError(f"refusing to overwrite existing file: {path}")
    write_exclusive(priv_path, private_pem(key, password))
    write_exclusive(pub_path, public_pem(key.public_key()))
    return priv_path, pub_path


def load_private(path: Path, password: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(read_bounded(path, 64 * 1024), password=password)
    except (ValueError, TypeError) as error:
        raise CryptoError("cannot load private key (wrong password or invalid PEM)") from error
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("private key is not an RSA key")
    return key


def load_public(path: Path) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(read_bounded(path, 64 * 1024))
    except ValueError as error:
        raise CryptoError("invalid public key PEM") from error
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("public key is not an RSA key")
    return key


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, as hex. Compare it out of band."""
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


# ----------------------------------------------------------------------- envelope

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise CryptoError(f"field {field} must be a Base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as error:
        raise CryptoError(f"field {field} is not valid Base64") from error


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def associated_data(envelope: dict) -> bytes:
    """AES-GCM AAD: the common fields except the ciphertext."""
    return canonical({k: envelope[k] for k in COMMON_FIELDS if k != "ciphertext"})


def signed_bytes(envelope: dict) -> bytes:
    """The signature covers every field except the signature itself."""
    return canonical({k: v for k, v in envelope.items() if k != "signature"})


def encrypt_message(plaintext: bytes, recipient: rsa.RSAPublicKey, mode: str = "hybrid",
                    sender_key: rsa.RSAPrivateKey | None = None) -> dict:
    """Build an envelope for `recipient`. Signs with `sender_key` unless it is None."""
    if mode not in MODES:
        raise CryptoError(f"unknown mode: {mode}")
    if len(plaintext) > MAX_SOURCE_BYTES:
        raise CryptoError(f"content is {len(plaintext)} bytes, limit is {MAX_SOURCE_BYTES}")

    envelope = {
        "version": VERSION,
        "mode": mode,
        "recipient": fingerprint(recipient),
        "sender": fingerprint(sender_key.public_key()) if sender_key else None,
        "signature_algorithm": SIGNATURE_ALGORITHM if sender_key else NO_SIGNATURE,
    }
    if mode == "rsa":
        limit = oaep_max_bytes(recipient)
        if len(plaintext) > limit:
            raise CryptoError(f"rsa mode accepts at most {limit} bytes; use --mode hybrid")
        envelope["ciphertext"] = b64e(recipient.encrypt(plaintext, oaep()))
    else:
        session_key = AESGCM.generate_key(bit_length=SESSION_KEY_BYTES * 8)
        nonce = os.urandom(NONCE_BYTES)
        envelope["wrapped_key"] = b64e(recipient.encrypt(session_key, oaep()))
        envelope["nonce"] = b64e(nonce)
        envelope["ciphertext"] = b64e(
            AESGCM(session_key).encrypt(nonce, plaintext, associated_data(envelope)))
    if sender_key:
        envelope["signature"] = b64e(sender_key.sign(signed_bytes(envelope), pss(), hashes.SHA256()))
    return envelope


def validate_envelope(envelope: object) -> dict:
    if not isinstance(envelope, dict):
        raise CryptoError("envelope must be a JSON object")
    if envelope.get("version") != VERSION:
        raise CryptoError("unsupported envelope version")
    mode = envelope.get("mode")
    if mode not in MODES:
        raise CryptoError("unknown mode")
    expected = set(COMMON_FIELDS)
    if mode == "hybrid":
        expected |= set(HYBRID_FIELDS)
    algorithm = envelope.get("signature_algorithm")
    if algorithm == SIGNATURE_ALGORITHM:
        expected.add("signature")
    elif algorithm != NO_SIGNATURE:
        raise CryptoError("unknown signature algorithm")
    present = set(envelope)
    if present != expected:
        missing, extra = sorted(expected - present), sorted(present - expected)
        raise CryptoError(f"invalid envelope fields (missing={missing}, extra={extra})")
    return envelope


def parse_envelope(raw: bytes) -> dict:
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise CryptoError("duplicate JSON keys in envelope")
        return dict(pairs)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise CryptoError("envelope too large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CryptoError("envelope is not valid JSON") from error
    return validate_envelope(data)


def decrypt_message(envelope: dict, recipient_key: rsa.RSAPrivateKey,
                    sender_public: rsa.RSAPublicKey | None = None,
                    allow_unsigned: bool = False) -> bytes:
    """Verify, then decrypt. A signature is required unless allow_unsigned=True."""
    envelope = validate_envelope(envelope)
    if envelope["recipient"] != fingerprint(recipient_key.public_key()):
        raise CryptoError("this envelope is not addressed to this key")

    signed = envelope["signature_algorithm"] == SIGNATURE_ALGORITHM
    if signed:
        if sender_public is None:
            raise CryptoError("signed envelope: the sender public key is required")
        if envelope["sender"] != fingerprint(sender_public):
            raise CryptoError("unexpected sender key")
        try:
            sender_public.verify(b64d(envelope["signature"], "signature"),
                                 signed_bytes(envelope), pss(), hashes.SHA256())
        except InvalidSignature as error:
            raise CryptoError("invalid signature: envelope rejected before decryption") from error
    elif not allow_unsigned:
        raise CryptoError("unsigned envelope refused (use --allow-unsigned on purpose)")

    try:
        if envelope["mode"] == "rsa":
            return recipient_key.decrypt(b64d(envelope["ciphertext"], "ciphertext"), oaep())
        session_key = recipient_key.decrypt(b64d(envelope["wrapped_key"], "wrapped_key"), oaep())
        nonce = b64d(envelope["nonce"], "nonce")
        if len(session_key) != SESSION_KEY_BYTES or len(nonce) != NONCE_BYTES:
            raise CryptoError("invalid session key or nonce length")
        return AESGCM(session_key).decrypt(nonce, b64d(envelope["ciphertext"], "ciphertext"),
                                           associated_data(envelope))
    except InvalidTag as error:
        raise CryptoError("AES-GCM authentication failed: content was modified") from error
    except ValueError as error:
        raise CryptoError("decryption failed") from error


# ---------------------------------------------------------------------------- demo

@dataclass
class Peer:
    name: str
    private: rsa.RSAPrivateKey

    @property
    def public(self) -> rsa.RSAPublicKey:
        return self.private.public_key()


def demo(bits: int, out=sys.stdout) -> None:
    """Alice and Bob: save/reload keys, RSA message, hybrid reply, 64 000-byte file, tampering."""
    say = lambda text: print(text, file=out)  # noqa: E731
    password = b"demo-password-not-a-secret"
    with tempfile.TemporaryDirectory() as tmp:
        say(f"== Demo with {bits}-bit RSA keys ==")
        peers = {}
        for name in ("alice", "bob"):
            priv, pub = save_key_pair(generate_keys(bits), Path(tmp), name, password)
            peers[name] = Peer(name, load_private(priv, password))
            assert fingerprint(load_public(pub)) == fingerprint(peers[name].public)
            say(f"[keys] {name}: saved and reloaded, fingerprint {fingerprint(peers[name].public)[:16]}...")
        alice, bob = peers["alice"], peers["bob"]

        message = "Bonjour Bob, rendez-vous à 14h. 🔐".encode("utf-8")
        env = encrypt_message(message, bob.public, "rsa", alice.private)
        assert decrypt_message(env, bob.private, alice.public) == message
        say(f"[rsa] Alice -> Bob: {len(message)} bytes (limit {oaep_max_bytes(bob.public)}), signature OK")

        reply = ("Merci Alice, c'est noté. " * 20).encode("utf-8")
        env = encrypt_message(reply, alice.public, "hybrid", bob.private)
        assert decrypt_message(env, alice.private, bob.public) == reply
        say(f"[hybrid] Bob -> Alice: {len(reply)} bytes, signature OK")

        blob = os.urandom(64_000)
        env = encrypt_message(blob, bob.public, "hybrid", alice.private)
        assert decrypt_message(env, bob.private, alice.public) == blob
        say("[hybrid] Alice -> Bob: 64000-byte content, received bytes identical")

        tampered = dict(env)
        raw = bytearray(b64d(tampered["ciphertext"], "ciphertext"))
        raw[0] ^= 1
        tampered["ciphertext"] = b64e(bytes(raw))
        try:
            decrypt_message(tampered, bob.private, alice.public)
            raise AssertionError("tampered envelope was accepted")
        except CryptoError as error:
            say(f"[tamper] modified envelope rejected: {error}")
        say("Demo finished: all checks passed.")


# ----------------------------------------------------------------------------- CLI

def ask_password(prompt: str, confirm: bool = False) -> bytes:
    password = getpass.getpass(prompt).encode("utf-8")
    if not password:
        raise CryptoError("empty password")
    if confirm and getpass.getpass("Confirm password: ").encode("utf-8") != password:
        raise CryptoError("passwords do not match")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RSA-OAEP / RSA-PSS / AES-GCM private messaging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a key pair")
    p.add_argument("--name", required=True)
    p.add_argument("--bits", type=int, choices=KEY_SIZES, default=2048)
    p.add_argument("--out-dir", type=Path, default=Path("keys"))

    p = sub.add_parser("fingerprint", help="print a public key fingerprint")
    p.add_argument("public_key", type=Path)

    p = sub.add_parser("encrypt", help="encrypt a message or a file")
    p.add_argument("--to", type=Path, required=True, help="recipient public key")
    p.add_argument("--from", dest="sender", type=Path, help="sender private key (signs)")
    p.add_argument("--no-sign", action="store_true", help="explicitly send without signature")
    p.add_argument("--mode", choices=MODES, default="hybrid")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--message")
    source.add_argument("--file", type=Path)
    p.add_argument("--out", type=Path, required=True, help="envelope JSON to create")

    p = sub.add_parser("decrypt", help="verify and decrypt an envelope")
    p.add_argument("--key", type=Path, required=True, help="recipient private key")
    p.add_argument("--sender", type=Path, help="expected sender public key")
    p.add_argument("--allow-unsigned", action="store_true")
    p.add_argument("--in", dest="envelope", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True, help="file to create with the plaintext")

    p = sub.add_parser("demo", help="run the Alice/Bob demonstration")
    p.add_argument("--bits", type=int, choices=KEY_SIZES, default=2048)
    return parser


def main(argv: list[str] | None = None, password_source=ask_password) -> int:
    args = build_parser().parse_args(argv)  # exits with code 2 on bad syntax
    try:
        if args.command == "keygen":
            password = password_source(f"Password for {args.name}'s private key: ", confirm=True)
            priv, pub = save_key_pair(generate_keys(args.bits), args.out_dir, args.name, password)
            print(f"Private key: {priv}\nPublic key:  {pub}")
            print(f"Fingerprint: {fingerprint(load_public(pub))}")
        elif args.command == "fingerprint":
            print(fingerprint(load_public(args.public_key)))
        elif args.command == "encrypt":
            if bool(args.sender) == args.no_sign:
                raise CryptoError("choose exactly one of --from (signed) or --no-sign")
            content = (args.message.encode("utf-8") if args.message is not None
                       else read_bounded(args.file, MAX_SOURCE_BYTES))
            sender_key = (load_private(args.sender, password_source("Sender key password: "))
                          if args.sender else None)
            envelope = encrypt_message(content, load_public(args.to), args.mode, sender_key)
            write_exclusive(args.out, json.dumps(envelope, indent=2).encode("utf-8"))
            print(f"Envelope written to {args.out}")
        elif args.command == "decrypt":
            envelope = parse_envelope(read_bounded(args.envelope, MAX_ENVELOPE_BYTES))
            key = load_private(args.key, password_source("Recipient key password: "))
            sender = load_public(args.sender) if args.sender else None
            plaintext = decrypt_message(envelope, key, sender, args.allow_unsigned)
            write_exclusive(args.out, plaintext)
            print(f"Plaintext ({len(plaintext)} bytes) written to {args.out}")
        elif args.command == "demo":
            demo(args.bits)
        return 0
    except (CryptoError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
