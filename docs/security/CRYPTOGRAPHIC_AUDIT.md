## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **First-Party Code Crypto Assets**: 4 | **Total Tracked Crypto Assets**: 7

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **0** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **3** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Digest** | **4** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **0.0%** | (0 of 3 asymmetric/vulnerable primitives migrated) |

### 🎯 Cryptographic Supply Chain Coverage & Confidence

| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |
|---|---|---|
| **First-Party Code (`src/`, `scripts/`)** | **100% Audited** (4 Crypto Primitive(s) Inventoried across Python (37), Shell (7)) | 🟢 **HIGH** (Direct AST & SAST verified) |
| **Third-Party Supply Chain** | **93.3%** (14 of 15 dependencies cataloged) | 🟢 HIGH (Known profiles assimilated) |
| **Overall Audit Confidence Score** | **93.8%** | 🟢 HIGH (1 unassimilated supply chain dependencies) |

| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |

### ✅ Post-Quantum Ready Assets

> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Provenance / Context |
|---|---|---|---|---|
| **`RSA-2048`**<br><sub>RSA-2048</sub> | algorithm / signature | 2048 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/signer.py:40`<br><sub><code>"Key-Type: RSA\n"</code></sub><br><br>`scripts/generate_signing_keys.sh:33`<br><sub><code>Key-Type: RSA</code></sub> |
| **`RSA-3072`**<br><sub>RSA-3072</sub> | algorithm / signature | 3072 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`scripts/verify_e2e_pipeline.sh:102`<br><sub><code>echo "  [PASS] GPG RSA-3072 key generation & idempotency verified (Fingerprint: ${FPR_FIRST})"</code></sub><br><br>`scripts/generate_signing_keys.sh:30`<br><sub><code>echo "[INFO] Generating RSA-3072 GPG Signing Key for ${GPG_KEY_NAME} <${GPG_KEY_EMAIL}>..."</code></sub> |
| **`certifi (Certifi Mozilla Root CA Bundle (RSA-2048/4096 & ECDSA P-256/P-384))`**<br><sub>RSA-2048 / ECDSA-P256</sub> | certificate / certificate | 2048-4096 | **Track Mozilla CA program transition to ML-DSA / SLH-DSA root trust anchors** | Assimilated Upstream CBOM: Certifi Mozilla CA Root Bundle<br>`Dependency: certifi@2025.1.31` |

### 🔒 Classical Symmetric & Digest Assets

| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Provenance / Location(s) |
|---|---|---|---|---|
| `SHA-256` | hash | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:18`<br>`gatekeeper/app/storage.py:59`<br>`gatekeeper/app/storage.py:85`<br>`gatekeeper/app/storage.py:86`<br>`gatekeeper/app/storage.py:102`<br>`gatekeeper/app/storage.py:112`<br>`gatekeeper/app/storage.py:118`<br>`gatekeeper/app/signer.py:138`<br>`gatekeeper/app/signer.py:150`<br>`gatekeeper/app/signer.py:157`<br>`gatekeeper/app/signer.py:158`<br>`gatekeeper/app/main.py:130`<br>`gatekeeper/app/main.py:292`<br>`gatekeeper/app/main.py:305`<br>`gatekeeper/app/main.py:336`<br>`gatekeeper/app/main.py:337`<br>`gatekeeper/app/main.py:345`<br>`gatekeeper/app/main.py:356`<br>`gatekeeper/app/main.py:357`<br>`gatekeeper/app/main.py:366`<br>`scripts/verify_e2e_pipeline.sh:165`<br>`scripts/verify_e2e_pipeline.sh:174`<br>`scripts/verify_e2e_pipeline.sh:176`<br>`scripts/verify_e2e_pipeline.sh:179` |
| `SHA-512` | hash | 512 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:19`<br>`gatekeeper/app/storage.py:58`<br>`gatekeeper/app/storage.py:60`<br>`gatekeeper/app/storage.py:65`<br>`gatekeeper/app/storage.py:74`<br>`gatekeeper/app/storage.py:88`<br>`gatekeeper/app/storage.py:89`<br>`gatekeeper/app/storage.py:109`<br>`gatekeeper/app/signer.py:139`<br>`gatekeeper/app/signer.py:151`<br>`gatekeeper/app/main.py:131`<br>`gatekeeper/app/main.py:273`<br>`gatekeeper/app/main.py:297`<br>`gatekeeper/app/main.py:518`<br>`gatekeeper/app/main.py:560`<br>`gatekeeper/app/main.py:569` |
| `httpcore (HTTPS Session TLS 1.2 / 1.3 Client)` | protocol | 256 | Quantum-Resistant (Grover's proof) | Assimilated Upstream CBOM: Python HTTPS/TLS & Cloud SDK Transport Profile<br>`Dependency: httpcore@1.0.7` |
| `httpx (HTTPS Session TLS 1.2 / 1.3 Client)` | protocol | 256 | Quantum-Resistant (Grover's proof) | Assimilated Upstream CBOM: Python HTTPS/TLS & Cloud SDK Transport Profile<br>`Dependency: httpx@0.27.2` |

### ⚠️ Unassimilated Third-Party Binaries & Cryptographic Blind Spots

> ℹ️ *The following third-party dependencies do not have verified upstream CBOM attestations in the catalog. They lower the audit confidence score until explicit CBOMs or attestations are published.* 

| Dependency Name | Version | Package URL (purl) | Status |
|---|---|---|---|
| `pydantic-settings` | 2.6.0 | `pkg:pypi/pydantic-settings@2.6.0` | 🟡 Unassimilated (No upstream CBOM) |
