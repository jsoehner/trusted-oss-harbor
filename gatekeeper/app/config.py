"""Configuration settings for the Trusted OSS Gatekeeper service."""

from pathlib import Path
from pydantic import Field
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
        default="https://repo.maven.apache.org/maven2", alias="UPSTREAM_MAVEN_URL"
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
        default="ChangeMe_GatekeeperToken_2026!", alias="GATEKEEPER_ADMIN_TOKEN"
    )

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
    def provenance_log_path(self) -> Path:
        return self.oss_data_root / "audit" / "provenance.jsonl"
