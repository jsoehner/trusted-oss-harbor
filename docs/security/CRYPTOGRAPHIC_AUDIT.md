## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **First-Party Code Crypto Assets**: 28 | **Total Tracked Crypto Assets**: 33

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **8** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **11** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Digest** | **14** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **42.1%** | (8 of 19 asymmetric/vulnerable primitives migrated) |

### 🎯 Cryptographic Supply Chain Coverage & Confidence

| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |
|---|---|---|
| **First-Party Code (`src/`, `scripts/`)** | **100% Audited** (28 Crypto Primitive(s) Inventoried across Configuration (9), Python (225), Shell (31)) | 🟢 **HIGH** (Direct AST & SAST verified) |
| **Third-Party Supply Chain** | **92.9%** (26 of 28 dependencies cataloged) | 🟢 HIGH (Known profiles assimilated) |
| **Overall Audit Confidence Score** | **93.1%** | 🟢 HIGH (2 unassimilated supply chain dependencies) |

| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |

### ✅ Post-Quantum Ready Assets

| Component Name | Primitive | Key/Parameter Set | PQC Standard | Provenance / Location(s) |
|---|---|---|---|---|
| `ML-DSA-65` | signature | 65 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`client-templates/pqc-verify.py:60`<br>`client-templates/pqc-verify.py:63`<br>`client-templates/pqc-verify.py:73`<br>`client-templates/github-actions-verify-component.yml:45`<br>`client-templates/github-actions-verify-component.yml:99`<br>`client-templates/github-actions-verify-component.yml:150`<br>`client-templates/github-actions-verify-component.yml:275`<br>`client-templates/github-actions-verify-component.yml:314`<br>`client-templates/github-actions-verify-component.yml:344`<br>`scripts/generate_signing_keys.sh:52`<br>`scripts/generate_signing_keys.sh:56`<br>`scripts/generate_signing_keys.sh:57`<br>`scripts/generate_signing_keys.sh:62`<br>`scripts/generate_signing_keys.sh:63`<br>`scripts/generate_signing_keys.sh:64`<br>`scripts/generate_signing_keys.sh:65`<br>`scripts/generate_signing_keys.sh:66`<br>`scripts/generate_signing_keys.sh:71`<br>`scripts/catalog_frontend.py:291`<br>`scripts/catalog_frontend.py:293`<br>`scripts/catalog_frontend.py:391`<br>`scripts/nas_entrypoint.sh:21`<br>`scripts/nas_entrypoint.sh:38`<br>`scripts/catalog_storage.py:13`<br>`scripts/catalog_storage.py:46`<br>`scripts/catalog_storage.py:103`<br>`scripts/catalog_storage.py:131`<br>`scripts/catalog_storage.py:154`<br>`scripts/verify_e2e_pipeline.sh:183`<br>`scripts/verify_e2e_pipeline.sh:184`<br>`scripts/verify_e2e_pipeline.sh:187`<br>`scripts/verify_e2e_pipeline.sh:188`<br>`scripts/verify_e2e_pipeline.sh:189`<br>`gatekeeper/app/config.py:144`<br>`gatekeeper/app/config.py:148`<br>`gatekeeper/app/config.py:152`<br>`gatekeeper/app/signer.py:1`<br>`gatekeeper/app/signer.py:13`<br>`gatekeeper/app/signer.py:21`<br>`gatekeeper/app/signer.py:24`<br>`gatekeeper/app/signer.py:28`<br>`gatekeeper/app/signer.py:31`<br>`gatekeeper/app/signer.py:35`<br>`gatekeeper/app/signer.py:72`<br>`gatekeeper/app/signer.py:77`<br>`gatekeeper/app/signer.py:78`<br>`gatekeeper/app/signer.py:79`<br>`gatekeeper/app/signer.py:82`<br>`gatekeeper/app/signer.py:99`<br>`gatekeeper/app/signer.py:100`<br>`gatekeeper/app/signer.py:105`<br>`gatekeeper/app/signer.py:111`<br>`gatekeeper/app/signer.py:113`<br>`gatekeeper/app/signer.py:127`<br>`gatekeeper/app/signer.py:135`<br>`gatekeeper/app/remediation.py:29`<br>`gatekeeper/app/remediation.py:36`<br>`gatekeeper/app/remediation.py:39`<br>`gatekeeper/app/remediation.py:209`<br>`gatekeeper/app/bom_generator.py:86`<br>`gatekeeper/app/storage.py:83`<br>`gatekeeper/app/storage.py:88`<br>`gatekeeper/app/storage.py:106`<br>`gatekeeper/app/storage.py:138`<br>`gatekeeper/app/storage.py:145`<br>`gatekeeper/app/main.py:422`<br>`gatekeeper/app/main.py:550`<br>`gatekeeper/app/main.py:580`<br>`gatekeeper/app/main.py:675`<br>`gatekeeper/app/main.py:721`<br>`gatekeeper/app/main.py:1009`<br>`gatekeeper/app/main.py:1012`<br>`gatekeeper/app/main.py:1015`<br>`gatekeeper/app/main.py:1032`<br>`gatekeeper/app/main.py:1033`<br>`gatekeeper/app/main.py:1037`<br>`gatekeeper/app/main.py:1050`<br>`gatekeeper/app/main.py:1094`<br>`gatekeeper/app/main.py:1097`<br>`gatekeeper/app/main.py:1100`<br>`gatekeeper/app/main.py:1122`<br>`gatekeeper/app/main.py:1123`<br>`gatekeeper/app/main.py:1127`<br>`gatekeeper/app/main.py:1140`<br>`gatekeeper/app/main.py:1503`<br>`gatekeeper/app/main.py:1528`<br>`gatekeeper/app/main.py:1810`<br>`gatekeeper/app/main.py:1855`<br>`gatekeeper/app/main.py:2172`<br>`gatekeeper/app/main.py:2418`<br>`gatekeeper/app/main.py:2422`<br>`gatekeeper/app/main.py:2425`<br>`gatekeeper/app/main.py:2429`<br>`gatekeeper/app/main.py:2433`<br>`gatekeeper/app/main.py:2435`<br>`gatekeeper/app/main.py:2437`<br>`gatekeeper/app/main.py:2553`<br>`gatekeeper/app/main.py:2556`<br>`gatekeeper/app/main.py:2559`<br>`gatekeeper/app/main.py:2576`<br>`gatekeeper/app/main.py:2577`<br>`gatekeeper/app/main.py:2581`<br>`gatekeeper/app/main.py:2672`<br>`gatekeeper/app/main.py:2675`<br>`gatekeeper/app/main.py:2678`<br>`gatekeeper/app/main.py:2698`<br>`gatekeeper/app/main.py:2699`<br>`gatekeeper/app/main.py:2703`<br>`gatekeeper/app/main.py:2896`<br>`gatekeeper/app/main.py:2916`<br>`gatekeeper/app/main.py:2936`<br>`gatekeeper/app/main.py:3149` |
| `X25519MLKEM768` | kem | X25519+ML-KEM-768 | Hybrid X25519+ML-KEM-768 (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:46` |
| `ML-KEM-1024` | kem | 1024 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:54` |
| `ML-KEM-768` | kem | 768 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:62` |
| `ML-KEM-512` | kem | 512 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:70` |
| `ML-DSA-87` | signature | 87 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:78` |
| `ML-DSA-44` | signature | 44 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:94` |
| `SLH-DSA` | signature | 128s/256f | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:102` |

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Provenance / Context |
|---|---|---|---|---|
| **`RSA-3072`**<br><sub>RSA-3072</sub> | algorithm / signature | 3072 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`scripts/generate_signing_keys.sh:30`<br><sub><code>echo "[INFO] Generating RSA-3072 GPG Signing Key for ${GPG_KEY_NAME} <${GPG_KEY_EMAIL}>..."</code></sub><br><br>`scripts/verify_e2e_pipeline.sh:102`<br><sub><code>echo "  [PASS] GPG RSA-3072 key generation & idempotency verified (Fingerprint: ${FPR_FIRST})"</code></sub> |
| **`RSA-2048`**<br><sub>RSA-2048</sub> | algorithm / signature | 2048 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`scripts/generate_signing_keys.sh:33`<br><sub><code>Key-Type: RSA</code></sub><br><br>`scripts/generate_mtls_keys.sh:12`<br><sub><code>openssl req -x509 -newkey rsa:4096 -sha384 -days 3650 -nodes \</code></sub><br><br>`scripts/generate_mtls_keys.sh:21`<br><sub><code>openssl req -newkey rsa:4096 -sha384 -nodes \</code></sub><br><br>`gatekeeper/app/signer.py:163`<br><sub><code>"Key-Type: RSA\n"</code></sub><br><br>`gatekeeper/app/bom_generator.py:111`<br><sub><code>"pattern": r"\b(?:RSA[-_]?PSS\|RS256\|RS384\|RS512\|RSAKey\|RSAPublicKey\|RSAPrivateKey\|RSA/ECB\|SHA256withRSA\|rsa\.generate_pr</code></sub> |
| **`ECDSA-P384`**<br><sub>ECDSA-P384</sub> | algorithm / signature | secp384r1 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:119`<br><sub><code>"pattern": r"\b(?:ECDSA\|ES256\|ES384\|ES512\|SHA256withECDSA\|ECPublicKey\|ECPrivateKey\|ec\.ECDSA\|SECP256R1\|SECP384R1\|prime25</code></sub> |
| **`ECDH-X25519`**<br><sub>ECDH-X25519</sub> | algorithm / key-agreement | 25519 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:127`<br><sub><code>"pattern": r"\b(?:ECDH\|ec\.ECDH\|X25519PrivateKey\|X25519PublicKey\|X25519)\b",</code></sub> |
| **`Ed25519`**<br><sub>Ed25519</sub> | algorithm / signature | 25519 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:135`<br><sub><code>"pattern": r"\b(?:Ed25519PrivateKey\|Ed25519PublicKey\|Ed25519\|EdDSA)\b",</code></sub> |
| **`Diffie-Hellman`**<br><sub>Diffie-Hellman</sub> | algorithm / key-agreement | 2048 | **ML-KEM (KEM) or ML-DSA (Signatures)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:143`<br><sub><code>"pattern": r"\b(?:DiffieHellman\|DHParameterSpec\|dh\.generate_parameters)\b",</code></sub> |
| **`MD5`**<br><sub>MD5</sub> | algorithm / hash | 128 | **SHA-256 / SHA-3-256 (FIPS 180-4 / FIPS 202)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:151`<br><sub><code>"pattern": r"\b(?:hashlib\.md5\|MD5\.new\|MessageDigest\.getInstance\(['\"]MD5['\"]\)\|EVP_md5)\b",</code></sub> |
| **`SHA-1`**<br><sub>SHA-1</sub> | algorithm / hash | 160 | **SHA-256 / SHA-3-256 (FIPS 180-4 / FIPS 202)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:159`<br><sub><code>"pattern": r"\b(?:hashlib\.sha1\|SHA1\.new\|MessageDigest\.getInstance\(['\"]SHA-?1['\"]\)\|EVP_sha1\|HMACSHA1)\b",</code></sub> |
| **`RC4`**<br><sub>RC4</sub> | algorithm / stream-cipher | 128 | **AES-256-GCM / ChaCha20-Poly1305 (RFC 5116 / RFC 8439)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:167`<br><sub><code>"pattern": r"\b(?:DESede\|TripleDES\|3DES\|RC4\|ARC4\|AES/ECB)\b",</code></sub> |
| **`certifi (Certifi Mozilla Root CA Bundle (RSA-2048/4096 & ECDSA P-256/P-384))`**<br><sub>RSA-2048 / ECDSA-P256</sub> | certificate / certificate | 2048-4096 | **Track Mozilla CA program transition to ML-DSA / SLH-DSA root trust anchors** | Assimilated Upstream CBOM: Certifi Mozilla CA Root Bundle<br>`Dependency: certifi@2025.1.31` |
| **`redis (Database TLS & Public Key Handshake)`**<br><sub>RSA-2048 / ECDSA-P256</sub> | signature / signature | 2048 / 256 | **Require TLS 1.3 with hybrid PQC key exchange on database connections** | Assimilated Upstream CBOM: Database Authentication & TLS Protocol Specification<br>`Dependency: redis@8.1.0` |

### 🔒 Classical Symmetric & Digest Assets

| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Provenance / Location(s) |
|---|---|---|---|---|
| `SHA-256` | hash | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`client-templates/github-actions-verify-component.yml:66`<br>`client-templates/github-actions-verify-component.yml:174`<br>`client-templates/github-actions-verify-component.yml:342`<br>`scripts/generate_signing_keys.sh:72`<br>`scripts/generate_signing_keys.sh:74`<br>`scripts/catalog_storage.py:44`<br>`scripts/catalog_storage.py:50`<br>`scripts/verify_e2e_pipeline.sh:166`<br>`scripts/verify_e2e_pipeline.sh:175`<br>`scripts/verify_e2e_pipeline.sh:177`<br>`scripts/verify_e2e_pipeline.sh:180`<br>`gatekeeper/app/signer.py:88`<br>`gatekeeper/app/signer.py:90`<br>`gatekeeper/app/signer.py:284`<br>`gatekeeper/app/signer.py:307`<br>`gatekeeper/app/remediation.py:30`<br>`gatekeeper/app/bom_generator.py:192`<br>`gatekeeper/app/bom_generator.py:468`<br>`gatekeeper/app/bom_generator.py:562`<br>`gatekeeper/app/bom_generator.py:563`<br>`gatekeeper/app/advisories.py:457`<br>`gatekeeper/app/advisories.py:459`<br>`gatekeeper/app/storage.py:18`<br>`gatekeeper/app/storage.py:60`<br>`gatekeeper/app/storage.py:69`<br>`gatekeeper/app/storage.py:110`<br>`gatekeeper/app/storage.py:111`<br>`gatekeeper/app/storage.py:131`<br>`gatekeeper/app/storage.py:141`<br>`gatekeeper/app/storage.py:149`<br>`gatekeeper/app/main.py:708`<br>`gatekeeper/app/main.py:715`<br>`gatekeeper/app/main.py:732`<br>`gatekeeper/app/main.py:740`<br>`gatekeeper/app/main.py:1016`<br>`gatekeeper/app/main.py:1045`<br>`gatekeeper/app/main.py:1058`<br>`gatekeeper/app/main.py:1101`<br>`gatekeeper/app/main.py:1135`<br>`gatekeeper/app/main.py:1148`<br>`gatekeeper/app/main.py:1231`<br>`gatekeeper/app/main.py:1232`<br>`gatekeeper/app/main.py:1240`<br>`gatekeeper/app/main.py:1255`<br>`gatekeeper/app/main.py:1256`<br>`gatekeeper/app/main.py:1265`<br>`gatekeeper/app/main.py:1292`<br>`gatekeeper/app/main.py:1293`<br>`gatekeeper/app/main.py:1302`<br>`gatekeeper/app/main.py:2166`<br>`gatekeeper/app/main.py:2560`<br>`gatekeeper/app/main.py:2679`<br>`gatekeeper/app/main.py:2901`<br>`gatekeeper/app/main.py:2937`<br>`gatekeeper/app/main.py:3144`<br>`gatekeeper/app/main.py:3151`<br>`gatekeeper/app/main.py:3172`<br>`gatekeeper/app/main.py:3203`<br>`gatekeeper/app/main.py:3215`<br>`gatekeeper/app/virtual_repo.py:50`<br>`gatekeeper/app/virtual_repo.py:51`<br>`gatekeeper/app/virtual_repo.py:54`<br>`gatekeeper/app/virtual_repo.py:55`<br>`gatekeeper/app/virtual_repo.py:61`<br>`gatekeeper/app/virtual_repo.py:116`<br>`gatekeeper/app/virtual_repo.py:123`<br>`gatekeeper/app/virtual_repo.py:150`<br>`gatekeeper/app/virtual_repo.py:151` |
| `SHA-384` | hash | 384 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`scripts/generate_signing_keys.sh:73`<br>`scripts/generate_mtls_keys.sh:12`<br>`scripts/generate_mtls_keys.sh:21`<br>`scripts/generate_mtls_keys.sh:41`<br>`gatekeeper/app/signer.py:89`<br>`gatekeeper/app/signer.py:289`<br>`gatekeeper/app/signer.py:308`<br>`gatekeeper/app/signer.py:324`<br>`gatekeeper/app/signer.py:325`<br>`gatekeeper/app/remediation.py:31`<br>`gatekeeper/app/bom_generator.py:200`<br>`gatekeeper/app/bom_generator.py:469`<br>`gatekeeper/app/bom_generator.py:470`<br>`gatekeeper/app/storage.py:20`<br>`gatekeeper/app/storage.py:61`<br>`gatekeeper/app/storage.py:71`<br>`gatekeeper/app/storage.py:113`<br>`gatekeeper/app/storage.py:114`<br>`gatekeeper/app/storage.py:115`<br>`gatekeeper/app/main.py:716`<br>`gatekeeper/app/main.py:1017`<br>`gatekeeper/app/main.py:1102`<br>`gatekeeper/app/main.py:2167`<br>`gatekeeper/app/main.py:2433`<br>`gatekeeper/app/main.py:2561`<br>`gatekeeper/app/main.py:2680`<br>`gatekeeper/app/main.py:2938` |
| `TLS-1.3` | protocol | v1.3 | TLS 1.3 Transport (Enable hybrid X25519MLKEM768 via OpenSSL 3.5+) | First-Party Code (SAST/AST)<br>`scripts/catalog_frontend.py:24` |
| `SHA-512` | hash | 512 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`scripts/catalog_storage.py:13`<br>`gatekeeper/app/signer.py:285`<br>`gatekeeper/app/signer.py:309`<br>`gatekeeper/app/remediation.py:32`<br>`gatekeeper/app/remediation.py:209`<br>`gatekeeper/app/bom_generator.py:208`<br>`gatekeeper/app/bom_generator.py:471`<br>`gatekeeper/app/bom_generator.py:472`<br>`gatekeeper/app/storage.py:19`<br>`gatekeeper/app/storage.py:59`<br>`gatekeeper/app/storage.py:62`<br>`gatekeeper/app/storage.py:70`<br>`gatekeeper/app/storage.py:117`<br>`gatekeeper/app/storage.py:118`<br>`gatekeeper/app/storage.py:138`<br>`gatekeeper/app/main.py:717`<br>`gatekeeper/app/main.py:1018`<br>`gatekeeper/app/main.py:1050`<br>`gatekeeper/app/main.py:1103`<br>`gatekeeper/app/main.py:1140`<br>`gatekeeper/app/main.py:1503`<br>`gatekeeper/app/main.py:1528`<br>`gatekeeper/app/main.py:2168`<br>`gatekeeper/app/main.py:2562`<br>`gatekeeper/app/main.py:2681`<br>`gatekeeper/app/main.py:2740`<br>`gatekeeper/app/main.py:2939`<br>`gatekeeper/app/main.py:3149` |
| `AES-256-GCM` | block-cipher | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:167`<br>`gatekeeper/app/bom_generator.py:176` |
| `ChaCha20-Poly1305` | stream-cipher | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:184` |
| `HMAC-SHA256` | mac | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:192` |
| `HMAC-SHA384` | mac | 384 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:200` |
| `HMAC-SHA512` | mac | 512 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:208` |
| `Argon2id` | kdf | 256 | Quantum-Resistant KDF / Password Hashing (Grover-resistant) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:216` |
| `X.509-Certificate` | certificate | X.509 | Review key length for Grover resistance | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:232` |
| `httpcore (HTTPS Session TLS 1.2 / 1.3 Client)` | protocol | 256 | Quantum-Resistant (Grover's proof) | Assimilated Upstream CBOM: Python HTTPS/TLS & Cloud SDK Transport Profile<br>`Dependency: httpcore@1.0.7` |
| `httpx (HTTPS Session TLS 1.2 / 1.3 Client)` | protocol | 256 | Quantum-Resistant (Grover's proof) | Assimilated Upstream CBOM: Python HTTPS/TLS & Cloud SDK Transport Profile<br>`Dependency: httpx@0.28.1` |
| `redis (Database SCRAM-SHA-256 / caching_sha2_password Digest & TLS Transport)` | hash | 256 | Quantum-Resistant (Grover's proof) | Assimilated Upstream CBOM: Database Authentication & TLS Protocol Specification<br>`Dependency: redis@8.1.0` |

### ⚠️ Unassimilated Third-Party Binaries & Cryptographic Blind Spots

> ℹ️ *The following third-party dependencies do not have verified upstream CBOM attestations in the catalog. They lower the audit confidence score until explicit CBOMs or attestations are published.* 

| Dependency Name | Version | Package URL (purl) | Status |
|---|---|---|---|
| `dilithium-py` | 1.5.1 | `pkg:pypi/dilithium-py@1.5.1` | 🟡 Unassimilated (No upstream CBOM) |
| `pydantic-settings` | 2.16.3 | `pkg:pypi/pydantic-settings@2.16.3` | 🟡 Unassimilated (No upstream CBOM) |

### ⚛️ Post-Quantum Cryptography (PQC) Modernization Roadmap

NIST finalized the principal post-quantum cryptography standards in August 2024: **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), and **FIPS 205** (SLH-DSA). Below is the recommended migration path for replacing quantum-vulnerable public key algorithms and hardening symmetric ciphers against Grover's algorithm.

#### 🗺️ Cryptographic Algorithm Replacement Matrix

| Classical Primitive | Threat Mechanism | Post-Quantum Replacement | NIST Security Level | Migration Guidance |
|---|---|---|---|---|
| **RSA / Diffie-Hellman / ECDH / X25519** (Key Exchange / KEM) | Broken by Shor's algorithm | **ML-KEM-768 / ML-KEM-1024** (FIPS 203) or Hybrid **X25519MLKEM768** | Level 3 (AES-192 equiv) / Level 5 (AES-256 equiv) | Primary general-purpose key encapsulation. For TLS 1.3 and SSH, deploy hybrid `X25519MLKEM768` for seamless interoperability. |
| **RSA-PSS / ECDSA / Ed25519** (Digital Signatures) | Broken by Shor's algorithm | **ML-DSA-65 / ML-DSA-87** (FIPS 204) | Level 3 / Level 5 | Primary general-purpose lattice signatures for PKI, X.509 certs, code signing, and API tokens. |
| **High-Assurance Root / CA Signatures** | Broken by Shor's algorithm | **SLH-DSA** (FIPS 205 / SPHINCS+) | Level 1, 3, 5 | Stateless hash-based signatures with zero lattice assumptions; ideal for long-lived root trust stores. |
| **Firmware / Secure Boot Signing** | Broken by Shor's algorithm | **LMS / XMSS** (RFC 8554 / RFC 8391, NIST SP 800-208) | Level 3 / Level 5 | Stateful hash-based signatures with minimal memory/code overhead; optimal for microcontrollers. |
| **AES-128 (Symmetric Encryption)** | Halved by Grover's (effective 64-bit security) | **AES-256-GCM** or **ChaCha20-Poly1305** | Level 5 (effective 128-bit quantum security) | Upgrade symmetric key lengths from 128-bit to 256-bit to preserve Grover resistance. |
| **SHA-1 / MD5 (Hash Functions)** | Broken classical collisions + quantum Grover | **SHA-256 / SHA-384 / SHA-512 / SHA-3-256** | Level 3 - 5 | Deprecate weak digests immediately. Use SHA-256 or SHA-3-256 as quantum-safe baseline. |

#### 💻 Multi-Language PQC Implementation Recipes

<details>
<summary><b>Swift (iOS, macOS, Server-side Swift)</b></summary>

```swift
import CryptoKit
// 1. Symmetric Grover resistance (use 256-bit keys)
let symmetricKey = SymmetricKey(size: .bits256)
let sealedBox = try AES.GCM.seal(data, using: symmetricKey)

// 2. Post-Quantum KEM via SwiftCrypto / liboqs-swift:
#if canImport(OQS)
import OQS
let kem = OQSKEM(algorithm: .mlkem768)
let (publicKey, secretKey) = try kem.generateKeyPair()
let (ciphertext, sharedSecretSender) = try kem.encapsulate(publicKey: publicKey)
let sharedSecretReceiver = try kem.decapsulate(ciphertext: ciphertext, secretKey: secretKey)
#endif
```
</details>

<details>
<summary><b>Go (Go 1.24+ crypto/mlkem & Hybrid TLS)</b></summary>

```go
package main

import (
    "crypto/mlkem" // Standard library in Go 1.24+
    "crypto/tls"
)

func main() {
    // 1. FIPS 203 ML-KEM-768 Key Encapsulation
    decapsKey, _ := mlkem.GenerateKey768()
    encapsKey := decapsKey.EncapsulationKey()
    ciphertext, sharedSecretClient := encapsKey.Encapsulate()
    sharedSecretServer, _ := decapsKey.Decapsulate(ciphertext)
    _ = sharedSecretServer

    // 2. Hybrid Post-Quantum TLS 1.3 Client
    tlsConfig := &tls.Config{
        MinVersion:       tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
    }
    _ = tlsConfig
}
```
</details>

<details>
<summary><b>Python (cryptography 44.0+ & liboqs-python)</b></summary>

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Grover-resistant 256-bit symmetric AEAD
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# 2. FIPS 203 ML-KEM-768 via liboqs-python
import oqs
with oqs.KeyEncapsulation('ML-KEM-768') as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret_sender = kem.encap_secret(public_key)
    shared_secret_receiver = kem.decap_secret(ciphertext)
    assert shared_secret_sender == shared_secret_receiver
```
</details>

<details>
<summary><b>Rust (pqcrypto / aws-lc-rs)</b></summary>

```rust
use pqcrypto_kyber::kyber768; // FIPS 203 ML-KEM-768
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};

fn main() {
    let (pk, sk) = kyber768::keypair();
    let (ss_sender, ct) = kyber768::encapsulate(&pk);
    let ss_receiver = kyber768::decapsulate(&ct, &sk);
    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
}
```
</details>

<details>
<summary><b>Java / Kotlin (Bouncy Castle 1.78+)</b></summary>

```java
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;
import java.security.*;

Security.addProvider(new BouncyCastlePQCProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
kpg.initialize(MLKEMParameterSpec.ml_kem_768);
KeyPair kp = kpg.generateKeyPair();
```
</details>

<details>
<summary><b>TypeScript / Node.js</b></summary>

```typescript
import { mlkem768 } from '@noble/post-quantum/ml-kem';

const [aliceKeys, alicePub] = mlkem768.keygen();
const [ciphertext, sharedBob] = mlkem768.encapsulate(alicePub);
const sharedAlice = mlkem768.decapsulate(ciphertext, aliceKeys);
```
</details>

### 🌐 Open Source CBOM Intelligence & Supply Chain Attestation Locators

Third-party dependencies account for the vast majority of cryptographic attack surfaces. When upstream packages do not ship with explicit CBOM files, use the following sources and methods to uncover cryptographic metadata:

1. **OCI 1.1 / Sigstore Cosign Attestations (`application/vnd.cyclonedx+json`)**:
   - Many open-source container images and libraries attach CycloneDX CBOM attestations via Sigstore Cosign.
   - Query attestations using Cosign:
     ```bash
     cosign download attestation --predicate-type https://cyclonedx.org/bom ghcr.io/<org>/<image>:<tag> | jq -r .payload | base64 -d | jq .
     ```
2. **OpenSSF Security Insights (`SECURITY-INSIGHTS.yml`)**:
   - Repositories implementing OpenSSF Security Insights declare encryption standards and key management under `/.github/SECURITY-INSIGHTS.yml`.
3. **Package Registry Provenance & Hash Attestations**:
   - **PyPI (PEP 740)**: Inspect cryptographic provenance via `https://pypi.org/pypi/<package>/json`.
   - **npm Provenance**: Verify build provenance and sign-offs with `npm view <package> --json`.
   - **Swift Package Index**: Discover cryptography framework dependencies directly from SwiftPM manifests and DocC documentation.
4. **Direct Assimilation with `--external-cbom`**:
   - Ingest any vendor or upstream CycloneDX CBOM file directly into `jsi-bom-actions`:
     ```bash
     python scripts/analyze_cbom.py build/cbom.cyclonedx.json --sbom build/sbom.cyclonedx.json --external-cbom vendor.cbom.json
     ```
   - This directly credits verified dependencies and elevates the repository's **Audit Confidence Score**.
