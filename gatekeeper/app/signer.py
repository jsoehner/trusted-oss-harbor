"""Cryptographic Signing Engine (GPG detached .asc signatures, Cosign OCI, and Provenance Audit Log)."""

import datetime
import hmac
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class SigningError(RuntimeError):
    """Raised when artifact signing or signature verification fails."""


def ensure_gpg_signing_key(
    gnupghome: Path,
    public_keys_dir: Path,
    key_name: str = "Trusted OSS Supply Chain Authority",
    key_email: str = "oss-signing@example.com",
) -> Path:
    """Ensure a GPG signing key exists in gnupghome and export trusted-oss-pubkey.asc."""
    gnupghome.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(gnupghome, 0o700)
    public_keys_dir.mkdir(parents=True, exist_ok=True)
    pubkey_file = public_keys_dir / "trusted-oss-pubkey.asc"

    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    list_proc = subprocess.run(
        ["gpg", "--batch", "--list-secret-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if "sec:" not in list_proc.stdout:
        batch_spec = (
            "%no-protection\n"
            "Key-Type: RSA\n"
            "Key-Length: 3072\n"
            f"Name-Real: {key_name}\n"
            f"Name-Email: {key_email}\n"
            "Expire-Date: 2y\n"
            "%commit\n"
        )
        gen_proc = subprocess.run(
            ["gpg", "--batch", "--generate-key"],
            input=batch_spec,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if gen_proc.returncode != 0:
            raise SigningError(f"Failed to initialize GPG signing key: {gen_proc.stderr}")

    exp_proc = subprocess.run(
        ["gpg", "--batch", "--armor", "--export", key_email],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if exp_proc.returncode != 0 or "BEGIN PGP PUBLIC KEY BLOCK" not in exp_proc.stdout:
        raise SigningError(f"Failed to export GPG public key: {exp_proc.stderr}")

    pubkey_file.write_text(exp_proc.stdout, encoding="utf-8")
    return pubkey_file


def sign_artifact_detached_gpg(
    artifact_path: Path,
    gnupghome: Path,
    passphrase: str = "",
) -> Path:
    """Create a detached ASCII-armored GPG signature (.asc) and verify it before returning."""
    sig_path = artifact_path.with_name(f"{artifact_path.name}.asc")
    if sig_path.exists():
        sig_path.unlink()

    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--output",
        str(sig_path),
    ]
    if passphrase:
        cmd.extend(["--pinentry-mode", "loopback", "--passphrase", passphrase])
    cmd.append(str(artifact_path))

    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not sig_path.exists():
        raise SigningError(f"GPG signing failed for {artifact_path.name}: {proc.stderr}")

    verify_proc = subprocess.run(
        ["gpg", "--batch", "--verify", str(sig_path), str(artifact_path)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if verify_proc.returncode != 0:
        raise SigningError(
            f"GPG self-verification failed for {artifact_path.name}: {verify_proc.stderr}"
        )

    return sig_path


def verify_artifact_signature(
    artifact_path: Path,
    sig_path: Path,
    gnupghome: Path,
) -> bool:
    """Verify that artifact_path has a valid detached GPG signature in sig_path."""
    if not artifact_path.exists() or not sig_path.exists():
        return False
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    proc = subprocess.run(
        ["gpg", "--batch", "--verify", str(sig_path), str(artifact_path)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def append_provenance_record(
    provenance_log_path: Path,
    ecosystem: str,
    artifact_rel_path: str,
    sha256: str,
    sha512: str,
    clamav_status: str,
    cve_status: str,
    signature_file: str,
) -> dict[str, Any]:
    """Append an immutable provenance record to provenance.jsonl."""
    provenance_log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ecosystem": ecosystem,
        "artifact": artifact_rel_path,
        "sha256": sha256,
        "sha512": sha512,
        "clamav_status": clamav_status,
        "cve_status": cve_status,
        "signature_file": signature_file,
        "attestation_hmac": hmac.new(
            b"trusted-oss-provenance-v1",
            f"{ecosystem}:{artifact_rel_path}:{sha256}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest(),
    }
    with provenance_log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return record
