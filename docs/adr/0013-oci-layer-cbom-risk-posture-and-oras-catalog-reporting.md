# ADR-0013: OCI Layer CBOM Risk Posture, X.509 Certificate Auditing, and ORAS/Catalog Reporting

- **Status:** Accepted
- **Date:** 2026-11-26
- **Deciders:** Security Architecture & Platform Engineering
- **Extends:** [ADR-0010](0010-signed-artifact-cbom-attestations-and-purl-batch-api.md) and [ADR-0012](0012-selectable-signature-verification-modes-and-oci-container-demo.md)

## Context

Under [ADR-0010](0010-signed-artifact-cbom-attestations-and-purl-batch-api.md), `generate_artifact_boms()` inspected only the staged file passed to `quarantine_scan_sign_and_promote()`. For OCI container images, that staged file is the 2 KB manifest or image index JSON. Because OCI manifests list only `sha256:` layer digests, Gatekeeper stamped container images `VERIFIED_INERT` (`crypto-asset-count: 0`) even when their layers contained OpenSSL 4.0, OpenJDK 27, active legacy providers, and 118 CA truststore certificates including SHA-1 root anchors.

Operators also need clear separation between:

1. **Active Risk vs. Passive Risk**: Expired certificates, non-CA leaf certs inside truststores, weak `<2048`-bit RSA keys, non-root SHA-1 chains, active OpenSSL legacy providers, and broken code calls (`MD5`, `SHA-1`, `RC4`) require immediate action (**Active Risk**). Self-signed SHA-1 root CAs, RFC 5280 `serial <= 0` legacy roots, policy-disabled runtime symbols (`libcrypto.so`, `lib/modules`), and quantum-vulnerable classical anchors carry latent or compliance exposure (**Passive Risk**).
2. **Compiled Risk vs. Coding Risk**: Modern base images ship PQC-capable runtimes (OpenSSL 4.0 `ML-KEM`/`ML-DSA`, OpenJDK 27 `ML-KEM`/`ML-DSA`) with low compiled risk, while application code may leave those PQC APIs unused (**medium coding risk**).

## Decision

1. **OCI Layer Inspection & Honest Uninspected Status (`gatekeeper/app/bom_generator.py`, `gatekeeper/app/main.py`):**
   - On OCI pull-through miss (when `OCI_BOM_DEEP_SCAN_ENABLED=true`), `fetch_upstream_oci_layers_for_bom()` downloads bounded platform layer tarballs (`OCI_BOM_MAX_LAYERS=16`, `OCI_BOM_MAX_LAYER_BYTES=120 MiB`) for in-memory inspection via `inspect_oci_layers()`, then deletes temporary layer files.
   - When Gatekeeper inspects an OCI manifest without layers (for example, `backfill_cached_boms()` or an upstream fetch failure), `generate_artifact_boms()` records `MANIFEST_ONLY_UNINSPECTED` instead of `VERIFIED_INERT`.
2. **Pure-Python X.509/JKS Certificate & Policy Risk Engine (`gatekeeper/app/crypto_risk.py`):**
   - Parse PEM bundles, DER certificates, and Java JKS (`0xFEEDFEED`) `cacerts` in pure Python without adding native dependencies to minimal Chainguard/Wolfi containers.
   - Audit every certificate for expiration, premature validity, non-CA truststore entries, `<2048`-bit RSA or DSA keys, non-positive serials, and SHA-1/MD5 signatures (separating self-signed SHA-1 root CAs from non-root chains).
   - Parse `openssl.cnf` (flagging activated `[legacy_sect]` / `CHAINGUARD_LEGACY_ALLOWED=1` and weak TLS floors), `java.security` (identifying `disabledAlgorithms` vs. active runtime exposure), and `/lib/apk/db/installed` OS packages.
   - Classify PQC adoption into `PQC_COMPILED_AND_USED`, `PQC_COMPILED_BUT_UNUSED`, `PQC_NOT_COMPILED_CLASSICAL_ONLY`, or `PQC_NOT_APPLICABLE_INERT`, reporting `pqc_compiled_risk`, `pqc_coding_risk`, and `pqc_ready_unused_libraries`.
3. **Core ORAS Referrers & Catalog Reporting:**
   - Enrich the CBOM descriptor in `GET /v2/{namespace}/{repo}/referrers/{digest}` with `trusted-oss.crypto.*` OCI 1.1 annotations so `oras discover` displays risk posture immediately.
   - Embed `crypto_posture` and aggregate counters in `GET /catalog/vulnerabilities`, add filterable `GET /catalog/crypto-risk`, include `risk_summary` in `/bom/lookup` and `/bom/batch`, and update `scripts/demo_container_acquisition_oras.ps1`, `scripts/trusted_container_demo.sh`, and `client-templates/github-actions-verify-component.yml`.

## Consequences

- **Positive:**
  - Eliminates false `VERIFIED_INERT` attestations on OCI container images while preserving a zero-dependency pure-Python Wolfi container build.
  - Exposes active vs. passive risk, expired/SHA-1 certificate hygiene, and PQC compiled-vs-coding gaps directly through core `oras discover` and `/catalog/*` queries.
- **Negative / Trade-offs:**
  - First-time OCI pull-through incurs additional upstream blob download time for layers up to `OCI_BOM_MAX_LAYER_BYTES` (`120 MiB`). Images exceeding the byte or layer cap skip oversized layers or fall back to `MANIFEST_ONLY_UNINSPECTED`.
  - Pure-Python X.509 parsing supports PEM, DER, and JKS stores; PKCS#12 truststores inside arbitrary layers require future PKCS#12 ASN.1 decoding if encountered.
