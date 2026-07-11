# open-infra's first-party Babelfish for PostgreSQL image.
#
# Built FROM the pinned community base (jonathanpotts/babelfishpg — a compiled
# Babelfish/Postgres, which is expensive to build from source) with our own
# start.sh layered on top so we control the entrypoint and can enable TLS on the
# TDS/PG listeners. Published to GHCR, Trivy-scanned, and cosign-signed by CI so the
# managed `engine: babelfish` depends on OUR registry at runtime, not a third party.
#
# The digest is pinned; bump it deliberately when adopting a newer Babelfish/PG.
FROM jonathanpotts/babelfishpg@sha256:8822d2bdc4e78b33f4b3dc576509799aada78b90220b5fc3ee3dfe210cfbc423

USER root
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
USER postgres

ENTRYPOINT ["/start.sh"]
