## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **First-Party Code Crypto Assets**: 33 | **Total Tracked Crypto Assets**: 38

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **8** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **16** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Digest** | **14** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **33.3%** | (8 of 24 asymmetric/vulnerable primitives migrated) |

### 🎯 Cryptographic Supply Chain Coverage & Confidence

| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |
|---|---|---|
| **First-Party Code (`src/`, `scripts/`)** | **100% Audited** (33 Crypto Primitive(s) Inventoried across Configuration (9), PowerShell (38), Python (313), Shell (70)) | 🟢 **HIGH** (Direct AST & SAST verified) |
| **Third-Party Supply Chain** | **92.9%** (26 of 28 dependencies cataloged) | 🟢 HIGH (Known profiles assimilated) |
| **Overall Audit Confidence Score** | **93.1%** | 🟢 HIGH (2 unassimilated supply chain dependencies) |

| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |

### ✅ Post-Quantum Ready Assets

| Component Name | Primitive | Key/Parameter Set | PQC Standard | Provenance / Location(s) |
|---|---|---|---|---|
| `ML-DSA-65` | signature | 65 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:88`<br>`gatekeeper/app/storage.py:93`<br>`gatekeeper/app/storage.py:111`<br>`gatekeeper/app/storage.py:143`<br>`gatekeeper/app/storage.py:150`<br>`gatekeeper/app/config.py:151`<br>`gatekeeper/app/config.py:155`<br>`gatekeeper/app/config.py:159`<br>`gatekeeper/app/main.py:427`<br>`gatekeeper/app/main.py:555`<br>`gatekeeper/app/main.py:586`<br>`gatekeeper/app/main.py:682`<br>`gatekeeper/app/main.py:728`<br>`gatekeeper/app/main.py:1164`<br>`gatekeeper/app/main.py:1167`<br>`gatekeeper/app/main.py:1170`<br>`gatekeeper/app/main.py:1187`<br>`gatekeeper/app/main.py:1188`<br>`gatekeeper/app/main.py:1192`<br>`gatekeeper/app/main.py:1205`<br>`gatekeeper/app/main.py:1249`<br>`gatekeeper/app/main.py:1252`<br>`gatekeeper/app/main.py:1255`<br>`gatekeeper/app/main.py:1277`<br>`gatekeeper/app/main.py:1278`<br>`gatekeeper/app/main.py:1282`<br>`gatekeeper/app/main.py:1295`<br>`gatekeeper/app/main.py:1658`<br>`gatekeeper/app/main.py:1683`<br>`gatekeeper/app/main.py:1966`<br>`gatekeeper/app/main.py:2013`<br>`gatekeeper/app/main.py:2399`<br>`gatekeeper/app/main.py:2645`<br>`gatekeeper/app/main.py:2649`<br>`gatekeeper/app/main.py:2652`<br>`gatekeeper/app/main.py:2656`<br>`gatekeeper/app/main.py:2660`<br>`gatekeeper/app/main.py:2662`<br>`gatekeeper/app/main.py:2664`<br>`gatekeeper/app/main.py:2780`<br>`gatekeeper/app/main.py:2783`<br>`gatekeeper/app/main.py:2786`<br>`gatekeeper/app/main.py:2803`<br>`gatekeeper/app/main.py:2804`<br>`gatekeeper/app/main.py:2808`<br>`gatekeeper/app/main.py:2899`<br>`gatekeeper/app/main.py:2902`<br>`gatekeeper/app/main.py:2905`<br>`gatekeeper/app/main.py:2925`<br>`gatekeeper/app/main.py:2926`<br>`gatekeeper/app/main.py:2930`<br>`gatekeeper/app/main.py:3123`<br>`gatekeeper/app/main.py:3145`<br>`gatekeeper/app/main.py:3197`<br>`gatekeeper/app/main.py:3464`<br>`gatekeeper/app/signer.py:1`<br>`gatekeeper/app/signer.py:13`<br>`gatekeeper/app/signer.py:21`<br>`gatekeeper/app/signer.py:24`<br>`gatekeeper/app/signer.py:28`<br>`gatekeeper/app/signer.py:31`<br>`gatekeeper/app/signer.py:35`<br>`gatekeeper/app/signer.py:72`<br>`gatekeeper/app/signer.py:77`<br>`gatekeeper/app/signer.py:78`<br>`gatekeeper/app/signer.py:79`<br>`gatekeeper/app/signer.py:82`<br>`gatekeeper/app/signer.py:99`<br>`gatekeeper/app/signer.py:100`<br>`gatekeeper/app/signer.py:105`<br>`gatekeeper/app/signer.py:111`<br>`gatekeeper/app/signer.py:113`<br>`gatekeeper/app/signer.py:127`<br>`gatekeeper/app/signer.py:135`<br>`gatekeeper/app/crypto_risk.py:36`<br>`gatekeeper/app/crypto_risk.py:75`<br>`gatekeeper/app/crypto_risk.py:92`<br>`gatekeeper/app/crypto_risk.py:93`<br>`gatekeeper/app/crypto_risk.py:104`<br>`gatekeeper/app/crypto_risk.py:268`<br>`gatekeeper/app/crypto_risk.py:473`<br>`gatekeeper/app/crypto_risk.py:1076`<br>`gatekeeper/app/bom_generator.py:108`<br>`gatekeeper/app/bom_generator.py:273`<br>`gatekeeper/app/bom_generator.py:276`<br>`gatekeeper/app/remediation.py:29`<br>`gatekeeper/app/remediation.py:36`<br>`gatekeeper/app/remediation.py:39`<br>`gatekeeper/app/remediation.py:209`<br>`client-templates/pqc-verify.py:60`<br>`client-templates/pqc-verify.py:63`<br>`client-templates/pqc-verify.py:73`<br>`client-templates/github-actions-verify-component.yml:45`<br>`client-templates/github-actions-verify-component.yml:105`<br>`client-templates/github-actions-verify-component.yml:158`<br>`client-templates/github-actions-verify-component.yml:286`<br>`client-templates/github-actions-verify-component.yml:329`<br>`client-templates/github-actions-verify-component.yml:361`<br>`scripts/catalog_frontend.py:291`<br>`scripts/catalog_frontend.py:293`<br>`scripts/catalog_frontend.py:391`<br>`scripts/verify_e2e_pipeline.sh:183`<br>`scripts/verify_e2e_pipeline.sh:184`<br>`scripts/verify_e2e_pipeline.sh:187`<br>`scripts/verify_e2e_pipeline.sh:188`<br>`scripts/verify_e2e_pipeline.sh:189`<br>`scripts/catalog_storage.py:13`<br>`scripts/catalog_storage.py:46`<br>`scripts/catalog_storage.py:103`<br>`scripts/catalog_storage.py:131`<br>`scripts/catalog_storage.py:154`<br>`scripts/nas_entrypoint.sh:22`<br>`scripts/nas_entrypoint.sh:40`<br>`scripts/trusted_container_demo.sh:54`<br>`scripts/trusted_container_demo.sh:110`<br>`scripts/trusted_container_demo.sh:114`<br>`scripts/trusted_container_demo.sh:120`<br>`scripts/trusted_container_demo.sh:249`<br>`scripts/trusted_container_demo.sh:250`<br>`scripts/trusted_container_demo.sh:251`<br>`scripts/trusted_container_demo.sh:252`<br>`scripts/trusted_container_demo.sh:253`<br>`scripts/trusted_container_demo.sh:322`<br>`scripts/trusted_container_demo.sh:328`<br>`scripts/trusted_container_demo.sh:359`<br>`scripts/trusted_container_demo.sh:360`<br>`scripts/trusted_container_demo.sh:361`<br>`scripts/trusted_container_demo.sh:367`<br>`scripts/trusted_container_demo.sh:371`<br>`scripts/trusted_container_demo.sh:385`<br>`scripts/trusted_container_demo.sh:388`<br>`scripts/trusted_container_demo.sh:408`<br>`scripts/trusted_container_demo.sh:409`<br>`scripts/trusted_container_demo.sh:412`<br>`scripts/generate_signing_keys.sh:52`<br>`scripts/generate_signing_keys.sh:56`<br>`scripts/generate_signing_keys.sh:57`<br>`scripts/generate_signing_keys.sh:62`<br>`scripts/generate_signing_keys.sh:63`<br>`scripts/generate_signing_keys.sh:64`<br>`scripts/generate_signing_keys.sh:65`<br>`scripts/generate_signing_keys.sh:66`<br>`scripts/generate_signing_keys.sh:71`<br>`scripts/demo_container_acquisition_oras.ps1:13`<br>`scripts/demo_container_acquisition_oras.ps1:852`<br>`scripts/demo_container_acquisition_oras.ps1:854`<br>`scripts/demo_container_acquisition_oras.ps1:856`<br>`scripts/demo_container_acquisition_oras.ps1:857`<br>`scripts/demo_container_acquisition_oras.ps1:859`<br>`scripts/demo_container_acquisition_oras.ps1:877`<br>`scripts/demo_container_acquisition_oras.ps1:954`<br>`scripts/demo_container_acquisition_oras.ps1:958`<br>`scripts/demo_container_acquisition_oras.ps1:960`<br>`scripts/demo_container_acquisition_oras.ps1:961`<br>`scripts/demo_container_acquisition_oras.ps1:964`<br>`scripts/demo_container_acquisition_oras.ps1:966`<br>`scripts/demo_container_acquisition_oras.ps1:977`<br>`scripts/demo_container_acquisition_oras.ps1:979`<br>`scripts/demo_container_acquisition_oras.ps1:986` |
| `ML-DSA-44` | signature | 44 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:35`<br>`gatekeeper/app/crypto_risk.py:76`<br>`gatekeeper/app/crypto_risk.py:266`<br>`gatekeeper/app/bom_generator.py:116`<br>`gatekeeper/app/bom_generator.py:275` |
| `ML-DSA-87` | signature | 87 | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:37`<br>`gatekeeper/app/crypto_risk.py:74`<br>`gatekeeper/app/crypto_risk.py:270`<br>`gatekeeper/app/crypto_risk.py:608`<br>`gatekeeper/app/bom_generator.py:100`<br>`gatekeeper/app/bom_generator.py:274` |
| `X25519MLKEM768` | kem | X25519+ML-KEM-768 | Hybrid X25519+ML-KEM-768 (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:70`<br>`gatekeeper/app/bom_generator.py:68` |
| `ML-KEM-1024` | kem | 1024 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:71`<br>`gatekeeper/app/crypto_risk.py:608`<br>`gatekeeper/app/bom_generator.py:76`<br>`gatekeeper/app/bom_generator.py:270` |
| `ML-KEM-768` | kem | 768 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:72`<br>`gatekeeper/app/crypto_risk.py:92`<br>`gatekeeper/app/crypto_risk.py:93`<br>`gatekeeper/app/crypto_risk.py:105`<br>`gatekeeper/app/crypto_risk.py:1076`<br>`gatekeeper/app/bom_generator.py:84`<br>`gatekeeper/app/bom_generator.py:269`<br>`gatekeeper/app/bom_generator.py:272` |
| `ML-KEM-512` | kem | 512 | ML-KEM (FIPS 203) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:73`<br>`gatekeeper/app/bom_generator.py:92`<br>`gatekeeper/app/bom_generator.py:271` |
| `SLH-DSA` | signature | 128s/256f | ML-DSA (FIPS 204) | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:77`<br>`gatekeeper/app/bom_generator.py:124` |

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Provenance / Context |
|---|---|---|---|---|
| **`RSA-2048`**<br><sub>RSA-2048</sub> | algorithm / signature | 2048 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/signer.py:163`<br><sub><code>"Key-Type: RSA\n"</code></sub><br><br>`gatekeeper/app/crypto_risk.py:84`<br><sub><code>{"RSA", "ECDSA", "ECDH-X25519", "Ed25519", "Diffie-Hellman"}</code></sub><br><br>`gatekeeper/app/crypto_risk.py:242`<br><sub><code>return f"RSA-{bits}", bits</code></sub><br><br>`gatekeeper/app/crypto_risk.py:243`<br><sub><code>return "RSA", 0</code></sub><br><br>`gatekeeper/app/crypto_risk.py:508`<br><sub><code>if (ktype.startswith("RSA-") and cert["key_bits"] < 2048) or ktype.startswith("DSA"):</code></sub><br><br>`gatekeeper/app/crypto_risk.py:663`<br><sub><code>allows_small_rsa = "RSA KEYSIZE < 1024" in cert_disabled.upper() and "RSA KEYSIZE < 2048" not in cert_disabled.upper()</code></sub><br><br>`gatekeeper/app/crypto_risk.py:845`<br><sub><code>"title": f"{cert_summary['weak_key_count']} certificate(s) with weak public keys (<2048-bit RSA or DSA)",</code></sub><br><br>`gatekeeper/app/crypto_risk.py:970`<br><sub><code>"detail": f"{jf['location']} specifies 'RSA keySize < 1024' rather than '< 2048'.",</code></sub><br><br>`gatekeeper/app/crypto_risk.py:1018`<br><sub><code>f"{cert_summary['total_unique'] - cert_summary.get('pqc_root_count', 0)} classical RSA/ECDSA trust anchors"</code></sub><br><br>`gatekeeper/app/bom_generator.py:133`<br><sub><code>"pattern": r"\b(?:RSA[-_]?PSS\|RS256\|RS384\|RS512\|RSAKey\|RSAPublicKey\|RSAPrivateKey\|RSA/ECB\|SHA256withRSA\|rsa\.generate_pr</code></sub><br><br>`gatekeeper/app/bom_generator.py:280`<br><sub><code>(b"SHA256withRSA", "RSA"),</code></sub><br><br>`scripts/generate_mtls_keys.sh:12`<br><sub><code>openssl req -x509 -newkey rsa:4096 -sha384 -days 3650 -nodes \</code></sub><br><br>`scripts/generate_mtls_keys.sh:21`<br><sub><code>openssl req -newkey rsa:4096 -sha384 -nodes \</code></sub><br><br>`scripts/generate_signing_keys.sh:33`<br><sub><code>Key-Type: RSA</code></sub> |
| **`ECDSA-P256`**<br><sub>ECDSA-P256</sub> | algorithm / signature | secp256r1 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:25`<br><sub><code>"1.2.840.10045.4.1": ("sha1", "ecdsa-with-SHA1"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:26`<br><sub><code>"1.2.840.10045.4.3.1": ("sha224", "ecdsa-with-SHA224"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:27`<br><sub><code>"1.2.840.10045.4.3.2": ("sha256", "ecdsa-with-SHA256"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:28`<br><sub><code>"1.2.840.10045.4.3.3": ("sha384", "ecdsa-with-SHA384"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:29`<br><sub><code>"1.2.840.10045.4.3.4": ("sha512", "ecdsa-with-SHA512"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:41`<br><sub><code>"1.2.840.10045.3.1.7": ("secp256r1", 256),</code></sub><br><br>`gatekeeper/app/bom_generator.py:279`<br><sub><code>(b"ECDSA", "ECDSA"),</code></sub> |
| **`Ed25519`**<br><sub>Ed25519</sub> | algorithm / signature | 25519 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:33`<br><sub><code>"1.3.101.112": ("ed25519", "Ed25519"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:34`<br><sub><code>"1.3.101.113": ("ed448", "Ed448"),</code></sub><br><br>`gatekeeper/app/crypto_risk.py:262`<br><sub><code>return "Ed25519", 256</code></sub><br><br>`gatekeeper/app/crypto_risk.py:264`<br><sub><code>return "Ed448", 448</code></sub><br><br>`gatekeeper/app/bom_generator.py:157`<br><sub><code>"pattern": r"\b(?:Ed25519PrivateKey\|Ed25519PublicKey\|Ed25519\|EdDSA)\b",</code></sub><br><br>`gatekeeper/app/bom_generator.py:278`<br><sub><code>(b"Ed25519", "Ed25519"),</code></sub> |
| **`ECDSA-P384`**<br><sub>ECDSA-P384</sub> | algorithm / signature | secp384r1 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:42`<br><sub><code>"1.3.132.0.34": ("secp384r1", 384),</code></sub><br><br>`gatekeeper/app/bom_generator.py:141`<br><sub><code>"pattern": r"\b(?:ECDSA\|ES256\|ES384\|ES512\|SHA256withECDSA\|ECPublicKey\|ECPrivateKey\|ec\.ECDSA\|SECP256R1\|SECP384R1\|prime25</code></sub> |
| **`ECDSA-P521`**<br><sub>ECDSA-P521</sub> | algorithm / signature | secp521r1 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:43`<br><sub><code>"1.3.132.0.35": ("secp521r1", 521),</code></sub> |
| **`ECDSA-secp256k1`**<br><sub>ECDSA-secp256k1</sub> | algorithm / signature | secp256k1 | **ML-DSA-65 / Dilithium (FIPS 204)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:44`<br><sub><code>"1.3.132.0.10": ("secp256k1", 256),</code></sub> |
| **`ECDH-X25519`**<br><sub>ECDH-X25519</sub> | algorithm / key-agreement | 25519 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:84`<br><sub><code>{"RSA", "ECDSA", "ECDH-X25519", "Ed25519", "Diffie-Hellman"}</code></sub><br><br>`gatekeeper/app/bom_generator.py:149`<br><sub><code>"pattern": r"\b(?:ECDH\|ec\.ECDH\|X25519PrivateKey\|X25519PublicKey\|X25519)\b",</code></sub><br><br>`gatekeeper/app/bom_generator.py:277`<br><sub><code>(b"X25519", "ECDH-X25519"),</code></sub> |
| **`TLS-1.0/1.1-Deprecated`**<br><sub>TLS-1.0/1.1-Deprecated</sub> | protocol / protocol | v1.1 | **TLS 1.3 with X25519MLKEM768 (RFC 8446 / FIPS 203)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:613`<br><sub><code>if min_proto and min_proto.strip().lower() in ("sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"):</code></sub><br><br>`gatekeeper/app/crypto_risk.py:659`<br><sub><code>for tok in ("SSLV3", "TLSV1", "TLSV1.1", "RC4", "DES", "3DES", "MD5", "SHA1"):</code></sub> |
| **`3DES`**<br><sub>3DES</sub> | algorithm / block-cipher | 112 | **AES-256-GCM / ChaCha20-Poly1305 (RFC 5116 / RFC 8439)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:659`<br><sub><code>for tok in ("SSLV3", "TLSV1", "TLSV1.1", "RC4", "DES", "3DES", "MD5", "SHA1"):</code></sub><br><br>`gatekeeper/app/bom_generator.py:288`<br><sub><code>(b"DESede", "Legacy-Weak-Cipher"),</code></sub> |
| **`RC4`**<br><sub>RC4</sub> | algorithm / stream-cipher | 128 | **AES-256-GCM / ChaCha20-Poly1305 (RFC 5116 / RFC 8439)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:659`<br><sub><code>for tok in ("SSLV3", "TLSV1", "TLSV1.1", "RC4", "DES", "3DES", "MD5", "SHA1"):</code></sub><br><br>`gatekeeper/app/bom_generator.py:189`<br><sub><code>"pattern": r"\b(?:DESede\|TripleDES\|3DES\|RC4\|ARC4\|AES/ECB)\b",</code></sub><br><br>`gatekeeper/app/bom_generator.py:289`<br><sub><code>(b"RC4", "Legacy-Weak-Cipher"),</code></sub> |
| **`Diffie-Hellman`**<br><sub>Diffie-Hellman</sub> | algorithm / key-agreement | 2048 | **ML-KEM (KEM) or ML-DSA (Signatures)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:165`<br><sub><code>"pattern": r"\b(?:DiffieHellman\|DHParameterSpec\|dh\.generate_parameters)\b",</code></sub> |
| **`MD5`**<br><sub>MD5</sub> | algorithm / hash | 128 | **SHA-256 / SHA-3-256 (FIPS 180-4 / FIPS 202)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:173`<br><sub><code>"pattern": r"\b(?:hashlib\.md5\|MD5\.new\|MessageDigest\.getInstance\(['\"]MD5['\"]\)\|EVP_md5)\b",</code></sub> |
| **`SHA-1`**<br><sub>SHA-1</sub> | algorithm / hash | 160 | **SHA-256 / SHA-3-256 (FIPS 180-4 / FIPS 202)** | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:181`<br><sub><code>"pattern": r"\b(?:hashlib\.sha1\|SHA1\.new\|MessageDigest\.getInstance\(['\"]SHA-?1['\"]\)\|EVP_sha1\|HMACSHA1)\b",</code></sub> |
| **`RSA-3072`**<br><sub>RSA-3072</sub> | algorithm / signature | 3072 | **ML-KEM-768 / Kyber (FIPS 203)** | First-Party Code (SAST/AST)<br>`scripts/verify_e2e_pipeline.sh:102`<br><sub><code>echo "  [PASS] GPG RSA-3072 key generation & idempotency verified (Fingerprint: ${FPR_FIRST})"</code></sub><br><br>`scripts/trusted_container_demo.sh:108`<br><sub><code>SIG_MODE_LABEL="Classical PGP/GPG Only (RSA-3072 .asc)"</code></sub><br><br>`scripts/trusted_container_demo.sh:320`<br><sub><code>echo "${PREFIX}    ├── Classical GPG (RSA-3072 .asc, $(human_size "${GPG_SIG_SIZE}"))"</code></sub><br><br>`scripts/trusted_container_demo.sh:325`<br><sub><code>echo "${PREFIX}    └── Classical GPG (RSA-3072 .asc, $(human_size "${GPG_SIG_SIZE}"))"</code></sub><br><br>`scripts/trusted_container_demo.sh:376`<br><sub><code>echo "  Verifying classical GPG (RSA-3072) detached signatures:"</code></sub><br><br>`scripts/generate_signing_keys.sh:30`<br><sub><code>echo "[INFO] Generating RSA-3072 GPG Signing Key for ${GPG_KEY_NAME} <${GPG_KEY_EMAIL}>..."</code></sub><br><br>`scripts/demo_container_acquisition_oras.ps1:886`<br><sub><code>Write-Section "3.3 Local Classical GPG (RSA-3072) Verification"</code></sub> |
| **`certifi (Certifi Mozilla Root CA Bundle (RSA-2048/4096 & ECDSA P-256/P-384))`**<br><sub>RSA-2048 / ECDSA-P256</sub> | certificate / certificate | 2048-4096 | **Track Mozilla CA program transition to ML-DSA / SLH-DSA root trust anchors** | Assimilated Upstream CBOM: Certifi Mozilla CA Root Bundle<br>`Dependency: certifi@2025.1.31` |
| **`redis (Database TLS & Public Key Handshake)`**<br><sub>RSA-2048 / ECDSA-P256</sub> | signature / signature | 2048 / 256 | **Require TLS 1.3 with hybrid PQC key exchange on database connections** | Assimilated Upstream CBOM: Database Authentication & TLS Protocol Specification<br>`Dependency: redis@8.1.0` |

### 🔒 Classical Symmetric & Digest Assets

| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Provenance / Location(s) |
|---|---|---|---|---|
| `SHA-256` | hash | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:21`<br>`gatekeeper/app/storage.py:65`<br>`gatekeeper/app/storage.py:74`<br>`gatekeeper/app/storage.py:115`<br>`gatekeeper/app/storage.py:116`<br>`gatekeeper/app/storage.py:136`<br>`gatekeeper/app/storage.py:146`<br>`gatekeeper/app/storage.py:154`<br>`gatekeeper/app/main.py:715`<br>`gatekeeper/app/main.py:722`<br>`gatekeeper/app/main.py:739`<br>`gatekeeper/app/main.py:747`<br>`gatekeeper/app/main.py:858`<br>`gatekeeper/app/main.py:874`<br>`gatekeeper/app/main.py:1171`<br>`gatekeeper/app/main.py:1200`<br>`gatekeeper/app/main.py:1213`<br>`gatekeeper/app/main.py:1256`<br>`gatekeeper/app/main.py:1290`<br>`gatekeeper/app/main.py:1303`<br>`gatekeeper/app/main.py:1386`<br>`gatekeeper/app/main.py:1387`<br>`gatekeeper/app/main.py:1395`<br>`gatekeeper/app/main.py:1410`<br>`gatekeeper/app/main.py:1411`<br>`gatekeeper/app/main.py:1420`<br>`gatekeeper/app/main.py:1447`<br>`gatekeeper/app/main.py:1448`<br>`gatekeeper/app/main.py:1457`<br>`gatekeeper/app/main.py:2393`<br>`gatekeeper/app/main.py:2787`<br>`gatekeeper/app/main.py:2906`<br>`gatekeeper/app/main.py:3128`<br>`gatekeeper/app/main.py:3198`<br>`gatekeeper/app/main.py:3241`<br>`gatekeeper/app/main.py:3459`<br>`gatekeeper/app/main.py:3466`<br>`gatekeeper/app/main.py:3510`<br>`gatekeeper/app/main.py:3538`<br>`gatekeeper/app/main.py:3550`<br>`gatekeeper/app/signer.py:88`<br>`gatekeeper/app/signer.py:90`<br>`gatekeeper/app/signer.py:284`<br>`gatekeeper/app/signer.py:307`<br>`gatekeeper/app/advisories.py:457`<br>`gatekeeper/app/advisories.py:459`<br>`gatekeeper/app/virtual_repo.py:50`<br>`gatekeeper/app/virtual_repo.py:51`<br>`gatekeeper/app/virtual_repo.py:54`<br>`gatekeeper/app/virtual_repo.py:55`<br>`gatekeeper/app/virtual_repo.py:61`<br>`gatekeeper/app/virtual_repo.py:116`<br>`gatekeeper/app/virtual_repo.py:123`<br>`gatekeeper/app/virtual_repo.py:150`<br>`gatekeeper/app/virtual_repo.py:151`<br>`gatekeeper/app/crypto_risk.py:20`<br>`gatekeeper/app/crypto_risk.py:27`<br>`gatekeeper/app/crypto_risk.py:31`<br>`gatekeeper/app/crypto_risk.py:62`<br>`gatekeeper/app/crypto_risk.py:218`<br>`gatekeeper/app/crypto_risk.py:220`<br>`gatekeeper/app/crypto_risk.py:336`<br>`gatekeeper/app/bom_generator.py:214`<br>`gatekeeper/app/bom_generator.py:283`<br>`gatekeeper/app/bom_generator.py:917`<br>`gatekeeper/app/bom_generator.py:1093`<br>`gatekeeper/app/bom_generator.py:1094`<br>`gatekeeper/app/remediation.py:30`<br>`client-templates/github-actions-verify-component.yml:66`<br>`client-templates/github-actions-verify-component.yml:182`<br>`client-templates/github-actions-verify-component.yml:359`<br>`scripts/verify_e2e_pipeline.sh:166`<br>`scripts/verify_e2e_pipeline.sh:175`<br>`scripts/verify_e2e_pipeline.sh:177`<br>`scripts/verify_e2e_pipeline.sh:180`<br>`scripts/catalog_storage.py:44`<br>`scripts/catalog_storage.py:50`<br>`scripts/trusted_container_demo.sh:191`<br>`scripts/trusted_container_demo.sh:195`<br>`scripts/trusted_container_demo.sh:217`<br>`scripts/trusted_container_demo.sh:244`<br>`scripts/trusted_container_demo.sh:252`<br>`scripts/trusted_container_demo.sh:256`<br>`scripts/trusted_container_demo.sh:257`<br>`scripts/trusted_container_demo.sh:361`<br>`scripts/trusted_container_demo.sh:362`<br>`scripts/trusted_container_demo.sh:365`<br>`scripts/trusted_container_demo.sh:423`<br>`scripts/trusted_container_demo.sh:433`<br>`scripts/trusted_container_demo.sh:443`<br>`scripts/trusted_container_demo.sh:454`<br>`scripts/generate_signing_keys.sh:72`<br>`scripts/generate_signing_keys.sh:74`<br>`scripts/demo_container_acquisition_oras.ps1:356`<br>`scripts/demo_container_acquisition_oras.ps1:357`<br>`scripts/demo_container_acquisition_oras.ps1:434`<br>`scripts/demo_container_acquisition_oras.ps1:638`<br>`scripts/demo_container_acquisition_oras.ps1:640`<br>`scripts/demo_container_acquisition_oras.ps1:644`<br>`scripts/demo_container_acquisition_oras.ps1:647`<br>`scripts/demo_container_acquisition_oras.ps1:649`<br>`scripts/demo_container_acquisition_oras.ps1:706`<br>`scripts/demo_container_acquisition_oras.ps1:710`<br>`scripts/demo_container_acquisition_oras.ps1:711`<br>`scripts/demo_container_acquisition_oras.ps1:713`<br>`scripts/demo_container_acquisition_oras.ps1:714`<br>`scripts/demo_container_acquisition_oras.ps1:754`<br>`scripts/demo_container_acquisition_oras.ps1:788`<br>`scripts/demo_container_acquisition_oras.ps1:1068`<br>`scripts/demo_container_acquisition_oras.ps1:1069`<br>`scripts/demo_container_acquisition_oras.ps1:1077`<br>`scripts/demo_container_acquisition_oras.ps1:1089` |
| `SHA-512` | hash | 512 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:22`<br>`gatekeeper/app/storage.py:64`<br>`gatekeeper/app/storage.py:67`<br>`gatekeeper/app/storage.py:75`<br>`gatekeeper/app/storage.py:122`<br>`gatekeeper/app/storage.py:123`<br>`gatekeeper/app/storage.py:143`<br>`gatekeeper/app/main.py:724`<br>`gatekeeper/app/main.py:1173`<br>`gatekeeper/app/main.py:1205`<br>`gatekeeper/app/main.py:1258`<br>`gatekeeper/app/main.py:1295`<br>`gatekeeper/app/main.py:1658`<br>`gatekeeper/app/main.py:1683`<br>`gatekeeper/app/main.py:2395`<br>`gatekeeper/app/main.py:2789`<br>`gatekeeper/app/main.py:2908`<br>`gatekeeper/app/main.py:2967`<br>`gatekeeper/app/main.py:3200`<br>`gatekeeper/app/main.py:3464`<br>`gatekeeper/app/signer.py:285`<br>`gatekeeper/app/signer.py:309`<br>`gatekeeper/app/crypto_risk.py:22`<br>`gatekeeper/app/crypto_risk.py:29`<br>`gatekeeper/app/crypto_risk.py:64`<br>`gatekeeper/app/bom_generator.py:230`<br>`gatekeeper/app/bom_generator.py:285`<br>`gatekeeper/app/bom_generator.py:920`<br>`gatekeeper/app/bom_generator.py:921`<br>`gatekeeper/app/remediation.py:32`<br>`gatekeeper/app/remediation.py:209`<br>`scripts/catalog_storage.py:13` |
| `SHA-384` | hash | 384 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/storage.py:23`<br>`gatekeeper/app/storage.py:66`<br>`gatekeeper/app/storage.py:76`<br>`gatekeeper/app/storage.py:118`<br>`gatekeeper/app/storage.py:119`<br>`gatekeeper/app/storage.py:120`<br>`gatekeeper/app/main.py:723`<br>`gatekeeper/app/main.py:1172`<br>`gatekeeper/app/main.py:1257`<br>`gatekeeper/app/main.py:2394`<br>`gatekeeper/app/main.py:2660`<br>`gatekeeper/app/main.py:2788`<br>`gatekeeper/app/main.py:2907`<br>`gatekeeper/app/main.py:3199`<br>`gatekeeper/app/signer.py:89`<br>`gatekeeper/app/signer.py:289`<br>`gatekeeper/app/signer.py:308`<br>`gatekeeper/app/signer.py:324`<br>`gatekeeper/app/signer.py:325`<br>`gatekeeper/app/crypto_risk.py:21`<br>`gatekeeper/app/crypto_risk.py:28`<br>`gatekeeper/app/crypto_risk.py:63`<br>`gatekeeper/app/bom_generator.py:222`<br>`gatekeeper/app/bom_generator.py:284`<br>`gatekeeper/app/bom_generator.py:918`<br>`gatekeeper/app/bom_generator.py:919`<br>`gatekeeper/app/remediation.py:31`<br>`scripts/generate_mtls_keys.sh:12`<br>`scripts/generate_mtls_keys.sh:21`<br>`scripts/generate_mtls_keys.sh:41`<br>`scripts/generate_signing_keys.sh:73`<br>`scripts/demo_container_acquisition_oras.ps1:14`<br>`scripts/demo_container_acquisition_oras.ps1:1064` |
| `X.509-Certificate` | certificate | X.509 | Review key length for Grover resistance | First-Party Code (SAST/AST)<br>`gatekeeper/app/crypto_risk.py:357`<br>`gatekeeper/app/crypto_risk.py:425`<br>`gatekeeper/app/bom_generator.py:254` |
| `AES-256-GCM` | block-cipher | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:189`<br>`gatekeeper/app/bom_generator.py:198`<br>`gatekeeper/app/bom_generator.py:281` |
| `ChaCha20-Poly1305` | stream-cipher | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:206`<br>`gatekeeper/app/bom_generator.py:282` |
| `HMAC-SHA256` | mac | 256 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:214` |
| `HMAC-SHA384` | mac | 384 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:222` |
| `HMAC-SHA512` | mac | 512 | Quantum-Resistant (Grover's proof) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:230` |
| `Argon2id` | kdf | 256 | Quantum-Resistant KDF / Password Hashing (Grover-resistant) | First-Party Code (SAST/AST)<br>`gatekeeper/app/bom_generator.py:238` |
| `TLS-1.3` | protocol | v1.3 | TLS 1.3 Transport (Enable hybrid X25519MLKEM768 via OpenSSL 3.5+) | First-Party Code (SAST/AST)<br>`scripts/catalog_frontend.py:24` |
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
