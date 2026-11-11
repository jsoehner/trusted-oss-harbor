# Changelog

All notable changes to `trusted-oss-harbor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-11

### Added
- **Post-Quantum Cryptography (PQC) Dual-Signing Engine**:
  - Integrated NIST FIPS 204 **ML-DSA-65** detached signing alongside legacy GPG RSA-3072.
  - Automatically signs promoted Maven and PyPI artifacts with both `.asc` and `.mldsa65` signatures, ensuring seamless zero-breaking-change backwards compatibility for classical clients while securing quantum-resistant verification.
- **PQC Public Key Distribution Endpoints**:
  - Exposed `GET /keys/trusted-oss-mldsa65.pub` serving ASCII-armored ML-DSA-65 public key material.
  - Exposed `GET /keys/trusted-oss-mldsa65.fingerprint` with SHA-256 and SHA-384 key fingerprints.
- **Grover-Resistant Hashing**:
  - Upgraded provenance logging (`audit/provenance.jsonl`) to compute and record SHA-384 digests and HMAC-SHA384 attestations alongside SHA-256 and SHA-512.
  - Automatically generated companion `.sha384` files alongside `.sha256` and `.sha512` during artifact promotion.
- **Client PQC Verification CLI**:
  - Added standalone `client-templates/pqc-verify.py` for client-side detached ML-DSA-65 verification.
- **Automated PQC Test Suite**:
  - Added unit and HTTP integration tests validating ML-DSA-65 key generation, signing, positive verification, tamper rejection, and dual-signature delivery.

### Changed
- Upgraded `gatekeeper` FastAPI application version to `0.2.0`.
- Updated `scripts/generate_signing_keys.sh` and `scripts/verify_e2e_pipeline.sh` to include ML-DSA-65 key generation and end-to-end verification.

## [0.1.0] - 2026-11-10

### Added
- Initial standalone release of `trusted-oss-harbor` supply chain platform.
- Dynamic pull-through quarantine for Maven and PyPI packages.
- ClamAV antivirus inspection via TCP `INSTREAM`.
- GPG RSA-3072 signing authority and read-time detached signature verification.
- Harbor Chainguard Proxy Cache configuration and shared Spring Boot catalog pre-warming.
- Automated 5-stage end-to-end verification harness.
