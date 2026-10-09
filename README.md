# Secure Messaging with RSA-OAEP, RSA-PSS and AES-256-GCM

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![cryptography](https://img.shields.io/badge/cryptography-50.0.1-blue)
![Tests](https://img.shields.io/badge/tests-20%20passing-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Context](https://img.shields.io/badge/Master%20AI%20%26%20Cybersecurity-Cryptography-6242ff)

A command-line **private messaging** tool for two peers, Alice and Bob. Each peer keeps its private key and shares its public key. Messages are **encrypted** for the recipient, **signed** by the sender and **verified before any decryption**. Long content uses **hybrid encryption** (RSA wraps an AES-256-GCM session key).

> Master's mini-project, **Cryptography** module, Master in AI & Cybersecurity (Faculté des Sciences de Kénitra), 2025–2026. This repository was rebuilt in October 2026 from the design and test plan in the project report; the tests and demo outputs in `preuves/` come from this code.

## Features

- RSA key pairs of **2048 or 3072 bits** (e = 65537); private key stored as **PKCS#8 PEM encrypted with a password**; existing files are never overwritten
- **SHA-256 fingerprints** of public keys, to compare out of band
- **`rsa` mode**: RSA-OAEP (SHA-256, MGF1-SHA-256) for short messages, max 190 bytes (2048-bit) or 318 bytes (3072-bit)
- **`hybrid` mode**: AES-256-GCM content + RSA-OAEP wrapped key, up to **8 MiB**
- **RSA-PSS (SHA-256, 32-byte salt) signatures**, required by default and checked **before** decryption
- Strict envelope validation: unknown mode/version, missing or extra fields, duplicate JSON keys and invalid Base64 are all rejected
- Nothing is written to disk when a check fails. Exit codes: `0` success, `1` error, `2` bad syntax

## How a signed hybrid message works

```text
Alice                                              Bob
  │ 1. random AES-256 key + 96-bit nonce
  │ 2. AES-GCM(content, AAD = envelope header)
  │ 3. RSA-OAEP(AES key, Bob's public key)
  │ 4. RSA-PSS sign(header + wrapped key + nonce + ciphertext)
  └──────────── envelope.json ───────────────────────►│
                                                      │ 5. recipient fingerprint matches?
                                                      │ 6. sender fingerprint matches expected key?
                                                      │ 7. verify signature  ── fail → reject
                                                      │ 8. unwrap key, AES-GCM decrypt ── tag fail → reject
                                                      ▼ plaintext written only if every check passed
```

Envelope fields: `version`, `mode`, `recipient`, `sender`, `signature_algorithm`, `ciphertext`, plus `wrapped_key` and `nonce` (hybrid) and `signature` (signed).

## Installation

```bash
git clone https://github.com/L3wina-debug/secure-messaging-rsa-aesgcm.git
cd secure-messaging-rsa-aesgcm
python -m pip install -r requirements.txt
```

## Usage

Run the full Alice/Bob scenario (keys saved and reloaded, RSA message, hybrid reply, 64 000-byte content, tampered envelope rejected):

```bash
python projet_rsa.py demo --bits 2048
python projet_rsa.py demo --bits 3072
```

Step by step:

```bash
python projet_rsa.py keygen --name alice --out-dir keys      # asks for a password twice
python projet_rsa.py keygen --name bob   --out-dir keys
python projet_rsa.py fingerprint keys/bob_public.pem          # compare with Bob by another channel

python projet_rsa.py encrypt --to keys/bob_public.pem --from keys/alice_private.pem \
       --message "Rendez-vous à 14h" --out msg.json             # hybrid + signed by default
python projet_rsa.py decrypt --key keys/bob_private.pem --sender keys/alice_public.pem \
       --in msg.json --out message.txt

python projet_rsa.py encrypt --to keys/bob_public.pem --from keys/alice_private.pem \
       --file report.pdf --out report.json                       # files up to 8 MiB
```

Unsigned messages need `--no-sign` on the sender side and `--allow-unsigned` on the receiver side: they protect confidentiality but do not prove who sent them.

## Tests

```bash
python -m unittest -v test_projet_rsa.py
```

**20 tests** cover Unicode messages, a 1 MiB binary file, the OAEP limits (190/191 and 318/319 bytes), the 8 MiB limit, a wrong recipient, sender key substitution, altered ciphertext, signature and GCM tag, unsigned envelopes refused by default, malformed envelopes (mode, version, fields, duplicate keys, Base64), password-protected PEM, no overwrite of existing files, and full CLI runs. Output: [`preuves/tests.txt`](preuves/tests.txt), demos: [`preuves/demo_2048.txt`](preuves/demo_2048.txt), [`preuves/demo_3072.txt`](preuves/demo_3072.txt).

## Threat model and limits

- An attacker can read, replace or modify envelopes in transit, but has no private key or password. The local computer is trusted.
- **Trust in public keys** depends on comparing fingerprints through an independent channel.
- **No replay protection** and **no forward secrecy**: a later compromise of a private RSA key can decrypt archived envelopes.
- Metadata (fingerprints, sizes) stays visible, and the same RSA key is used for encryption and signing.
- Transport is simulated with JSON files; there is no network service. On Windows, protect the `keys/` folder with NTFS permissions.

This is a functional, tested prototype for learning, not a security audit. A real system should use an established, audited protocol.

## What I learned

- **Why hybrid encryption:** RSA-OAEP can only encrypt `k − 2·hLen − 2` bytes, so RSA protects a session key and AES-GCM protects the content.
- **Authenticated encryption and AAD:** binding the envelope header to the ciphertext so a modified header is detected.
- **Sign-then-verify order:** checking the RSA-PSS signature before decrypting, so forged envelopes never reach the decryption code.
- **Key management:** encrypted PKCS#8 storage, fingerprints, and refusing to overwrite files.
- **Testing security properties:** writing tests that prove tampering, wrong keys and malformed input are rejected, not only that the happy path works.

## Author

**Mahmoud El Aaouadi**, Master's student in AI & Cybersecurity. [Portfolio](https://mahmoud-elaaouadi.netlify.app) · [LinkedIn](https://www.linkedin.com/in/mahmoud-elaaouadi-7b3087416)

## License

[MIT](LICENSE)
