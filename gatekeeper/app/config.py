"""Configuration settings for the Trusted OSS Gatekeeper service."""

from pathlib import Path
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    oss_data_root: Path = Field(default=Path("/home/jsoehner/trusted-oss-data"), alias="OSS_DATA_ROOT")
    clamav_host: str = Field(default="clamav", alias="CLAMAV_HOST")
    clamav_port: int = Field(default=3310, alias="CLAMAV_PORT")
    clamav_required: bool = Field(default=True, alias="CLAMAV_REQUIRED")
    cvss_fail_threshold: float = Field(default=7.0, alias="CVSS_FAIL_THRESHOLD")
    auto_promote_clean_artifacts: bool = Field(
        default=True, alias="AUTO_PROMOTE_CLEAN_ARTIFACTS"
    )
    upstream_maven_url: str = Field(
        default="https://maven-central.storage-download.googleapis.com/maven2,https://repo.maven.apache.org/maven2,https://repo.spring.io/milestone",
        alias="UPSTREAM_MAVEN_URL",
    )
    upstream_pypi_simple_url: str = Field(
        default="https://pypi.org/simple", alias="UPSTREAM_PYPI_SIMPLE_URL"
    )
    upstream_chainguard_url: str = Field(
        default="https://cgr.dev", alias="UPSTREAM_CHAINGUARD_URL"
    )
    seed_catalog_path: Path = Field(
        default=Path(__file__).resolve().parents[2]
        / "config"
        / "catalog"
        / "trusted-seed-catalog.json",
        alias="SEED_CATALOG_PATH",
    )
    gnupghome: Path = Field(
        default=Path("/home/jsoehner/trusted-oss-data/keys/gnupg"), alias="GNUPGHOME"
    )
    gpg_key_id: str = Field(default="", alias="GPG_KEY_ID")
    gpg_passphrase: str = Field(default="", alias="GPG_PASSPHRASE")
    cosign_private_key_path: Path = Field(
        default=Path("/home/jsoehner/trusted-oss-data/keys/cosign/cosign.key"),
        alias="COSIGN_PRIVATE_KEY_PATH",
    )
    cosign_public_key_path: Path = Field(
        default=Path("/home/jsoehner/trusted-oss-data/keys/cosign/cosign.pub"),
        alias="COSIGN_PUBLIC_KEY_PATH",
    )
    gatekeeper_admin_token: str = Field(
        default="", alias="GATEKEEPER_ADMIN_TOKEN"
    )
    allow_simulated_cvss: bool = Field(default=False, alias="ALLOW_SIMULATED_CVSS")
    pqc_signing_enabled: bool = Field(default=True, alias="PQC_SIGNING_ENABLED")
    virtual_repo_enabled: bool = Field(default=True, alias="VIRTUAL_REPO_ENABLED")
    cve_scanner_mode: str = Field(default="auto", alias="CVE_SCANNER_MODE")
    workspace_scan_roots: str = Field(default="", alias="WORKSPACE_SCAN_ROOTS")
    github_username: str = Field(default="jsoehner", alias="GITHUB_USERNAME")
    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    warmup_concurrency: int = Field(default=4, alias="WARMUP_CONCURRENCY")
    trusted_sources: list[str] = Field(
        default=["cgr.dev", "docker.io", "ghcr.io", "quay.io"],
        alias="TRUSTED_SOURCES",
    )

    @model_validator(mode="after")
    def resolve_dynamic_paths(self) -> "Settings":
        """Dynamically re-anchor default child paths if oss_data_root was customized."""
        default_root = Path("/home/jsoehner/trusted-oss-data")
        if self.oss_data_root != default_root:
            if self.gnupghome == default_root / "keys" / "gnupg":
                self.gnupghome = self.oss_data_root / "keys" / "gnupg"
            if self.cosign_private_key_path == default_root / "keys" / "cosign" / "cosign.key":
                self.cosign_private_key_path = self.oss_data_root / "keys" / "cosign" / "cosign.key"
            if self.cosign_public_key_path == default_root / "keys" / "cosign" / "cosign.pub":
                self.cosign_public_key_path = self.oss_data_root / "keys" / "cosign" / "cosign.pub"

        if not self.seed_catalog_path.is_file():
            for candidate in (
                Path("/app/config/catalog/trusted-seed-catalog.json"),
                Path("/config/catalog/trusted-seed-catalog.json"),
                Path(__file__).resolve().parents[1] / "config" / "catalog" / "trusted-seed-catalog.json",
                Path(__file__).resolve().parents[2] / "config" / "catalog" / "trusted-seed-catalog.json",
            ):
                if candidate.is_file():
                    self.seed_catalog_path = candidate
                    break
        return self

    @property
    def quarantine_dir(self) -> Path:
        return self.oss_data_root / "packages" / "quarantine"

    @property
    def trusted_maven_dir(self) -> Path:
        return self.oss_data_root / "packages" / "trusted-maven"

    @property
    def trusted_pypi_dir(self) -> Path:
        return self.oss_data_root / "packages" / "trusted-pypi"

    @property
    def harbor_oci_cache_dir(self) -> Path:
        return self.oss_data_root / "harbor" / "registry" / "chainguard-cache"

    @property
    def public_keys_dir(self) -> Path:
        return self.oss_data_root / "keys" / "public"

    @property
    def mldsa_keys_dir(self) -> Path:
        return self.oss_data_root / "keys" / "mldsa"

    @property
    def mldsa_private_key_path(self) -> Path:
        return self.mldsa_keys_dir / "trusted-oss-mldsa65.key"

    @property
    def mldsa_public_key_path(self) -> Path:
        return self.public_keys_dir / "trusted-oss-mldsa65.pub"

    @property
    def provenance_log_path(self) -> Path:
        return self.oss_data_root / "audit" / "provenance.jsonl"
