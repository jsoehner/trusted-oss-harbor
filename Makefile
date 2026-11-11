.PHONY: help init-storage generate-keys sync-nvd bootstrap-harbor up down logs test verify-e2e iscsi-roadmap-dryrun build-appliance run-appliance push-appliance

SHELL := /usr/bin/bash
include .env.example
-include .env
export

help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

init-storage: ## Create persistent storage directory hierarchy under OSS_DATA_ROOT (/home/jsoehner/trusted-oss-data)
	bash scripts/bootstrap_host.sh --init-storage-only

generate-keys: ## Generate Trusted OSS GPG keypair and Cosign OCI signing keypair
	bash scripts/generate_signing_keys.sh

sync-nvd: ## Seed OWASP NVD H2 database from jsoehner/nvd-cache into persistent store
	bash scripts/bootstrap_host.sh --sync-nvd-only

bootstrap-harbor: ## Download Harbor installer, render harbor.yml, and initialize storage
	bash scripts/bootstrap_host.sh

up: ## Start ClamAV, Harbor Scanner Adapter, OSS Gatekeeper, and Unified Gateway
	docker compose up -d --build

down: ## Stop all Trusted OSS services
	docker compose down

logs: ## Tail logs from all Trusted OSS services
	docker compose logs -f

test: ## Run unit and integration test suite for the Quarantine-Scan-Sign Gatekeeper
	pytest gatekeeper/tests -v

verify-e2e: ## Run end-to-end verification of Quarantine -> ClamAV -> Trivy -> GPG Sign -> Trusted serve
	bash scripts/verify_e2e_pipeline.sh

configure-harbor-chainguard: ## Provision Harbor 'chainguard-cache' Proxy Cache project for cgr.dev/chainguard/{jre,python}
	bash scripts/configure_harbor_projects.sh

iscsi-roadmap-dryrun: ## Preview TrueNAS iSCSI block storage attachment & migration commands
	bash scripts/setup_truenas_iscsi_mount.sh --dry-run --migrate

build-appliance: ## Build standalone all-in-one NAS appliance Docker image
	docker build -t ghcr.io/jsoehner/trusted-oss-gatekeeper:latest -t ghcr.io/jsoehner/trusted-oss-gatekeeper:$$(cat VERSION) .

run-appliance: ## Run standalone all-in-one NAS appliance container locally on port 8080
	docker run --rm -it \
		--name trusted-oss-gatekeeper \
		-p 8080:8080 \
		-v $${OSS_DATA_ROOT:-/home/jsoehner/trusted-oss-data}:/data \
		ghcr.io/jsoehner/trusted-oss-gatekeeper:latest

push-appliance: ## Push standalone NAS appliance image to GitHub Container Registry
	docker push ghcr.io/jsoehner/trusted-oss-gatekeeper:latest
	docker push ghcr.io/jsoehner/trusted-oss-gatekeeper:$$(cat VERSION)
