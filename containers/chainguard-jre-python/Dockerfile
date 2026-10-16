# ==============================================================================
# Golden Chainguard JRE + Python Runtime Container via Harbor Proxy Cache
# ==============================================================================
# Demonstrates pulling Chainguard's zero-CVE Python and JRE images exclusively
# through your self-hosted Harbor Proxy Cache (${HARBOR_REGISTRY}/chainguard-cache)
# for polyglot Spring Boot + Python AI workloads (e.g., spring-ai-blog-agent
# and enterprise-command-center).
# ==============================================================================

ARG HARBOR_REGISTRY=oss.example.com
ARG CHAINGUARD_PROJECT=chainguard-cache

# Stage 1: Pull & cache Chainguard Python runtime via Harbor Proxy Cache
FROM ${HARBOR_REGISTRY}/${CHAINGUARD_PROJECT}/chainguard/python:latest AS python-runtime

# Stage 2: Pull & cache Chainguard JRE runtime via Harbor Proxy Cache
FROM ${HARBOR_REGISTRY}/${CHAINGUARD_PROJECT}/chainguard/jre:latest AS golden-jre-python

# Copy verified Python 3 interpreter and stdlib from the cached Chainguard Python image
COPY --from=python-runtime /usr/bin/python* /usr/bin/
COPY --from=python-runtime /usr/lib/python* /usr/lib/
COPY --from=python-runtime /lib/ /lib/

WORKDIR /app

# Run as Chainguard's unprivileged nonroot user (UID 65532)
USER 65532:65532

ENTRYPOINT ["java", "-version"]
