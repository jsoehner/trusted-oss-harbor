    trusted_sources: list[str] = Field(
        default=["cgr.dev", "docker.io", "ghcr.io", "quay.io"],
        alias="TRUSTED_SOURCES"
    )
