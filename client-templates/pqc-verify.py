#!/usr/bin/env python3
"""
pqc-verify.py - Client-side detached Post-Quantum Cryptography (PQC) Signature Verifier

Verifies detached NIST FIPS 204 ML-DSA-65 signatures (.mldsa65) on software artifacts (.jar, .whl, .tar.gz)
against Trusted OSS Harbor public keys (/keys/trusted-oss-mldsa65.pub).

Usage:
    python3 pqc-verify.py <artifact_file> <signature_file> <public_key_file>
"""

import sys
import base64
from pathlib import Path


def dearmor(content: bytes | str) -> bytes:
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            return content
    else:
        text = content

    if "-----BEGIN " in text and "-----END " in text:
        clean_lines = [
            line.strip()
            for line in text.strip().splitlines()
            if not line.startswith("-----")
        ]
        return base64.b64decode("".join(clean_lines))

    return content if isinstance(content, bytes) else content.encode("utf-8")


def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: python3 pqc-verify.py <artifact_file> <signature_file> <public_key_file>",
            file=sys.stderr,
        )
        sys.exit(2)

    artifact_path = Path(sys.argv[1])
    sig_path = Path(sys.argv[2])
    pubkey_path = Path(sys.argv[3])

    if not artifact_path.exists():
        print(f"Error: Artifact file not found: {artifact_path}", file=sys.stderr)
        sys.exit(1)
    if not sig_path.exists():
        print(f"Error: Signature file not found: {sig_path}", file=sys.stderr)
        sys.exit(1)
    if not pubkey_path.exists():
        print(f"Error: Public key file not found: {pubkey_path}", file=sys.stderr)
        sys.exit(1)

    try:
        from dilithium_py.dilithium import Dilithium3
    except ImportError:
        print(
            "Error: dilithium-py not installed. Install via: pip install dilithium-py",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        data = artifact_path.read_bytes()
        sig = dearmor(sig_path.read_bytes())
        pk = dearmor(pubkey_path.read_bytes())

        if Dilithium3.verify(pk, data, sig):
            print(f"[OK] NIST FIPS 204 ML-DSA-65 Signature Verified: {artifact_path.name}")
            sys.exit(0)
        else:
            print(
                f"[FAIL] Cryptographic signature verification failed for: {artifact_path.name}",
                file=sys.stderr,
            )
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Signature verification exception: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
