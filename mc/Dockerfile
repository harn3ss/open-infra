# open-infra-mc — the MinIO client (`mc`) with a WORLD-READABLE binary.
#
# The stock minio/mc image ships /usr/bin/mc without world-read (mode ~0750, root-owned), so the
# `fetch-mc` init containers in the WORM audit / attestation / crypto-erase jobs — which stage mc into a
# shared emptyDir for a hardened, non-root main container — could only copy it by running as ROOT. That
# is rejected under `restricted` Pod Security, and it was ALSO already failing on the plain cluster where
# those inits run non-root (the encryptionkey-destroyer sat in Init:Error). Re-materializing mc at 0755
# lets the copy run as an unprivileged user, so those pods become restricted-PSA clean.
FROM minio/mc:latest AS src

FROM alpine:3.20
COPY --from=src /usr/bin/mc /usr/bin/mc
RUN chmod 0755 /usr/bin/mc && /usr/bin/mc --version
USER 65532:65532
ENTRYPOINT ["/usr/bin/mc"]
