FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
    -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# guacone CLI is used to push raw SBOM/VEX documents directly to graphql-server,
# bypassing ingestor's DSSE verification (which rejects keyless cosign sigs).
# Copy the static binary out of the official GUAC image — no need to rebuild
# the Go toolchain here.
COPY --from=ghcr.io/guacsec/guac:v1.1.0 /opt/guac/guacone /usr/local/bin/guacone

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY proto /app/proto
COPY src /app/src

# Generate the GUAC collectsub gRPC stubs into the package directory.
# Kept inside the image (not committed) so the generated files stay in sync
# with the grpcio/protobuf versions pinned in requirements.txt.
RUN pip install --no-cache-dir grpcio-tools==1.66.1 \
    && python -m grpc_tools.protoc \
        -I /app/proto \
        --python_out=/app/src/zta_operator/_grpc \
        --grpc_python_out=/app/src/zta_operator/_grpc \
        /app/proto/collectsub.proto \
    && pip uninstall -y grpcio-tools \
    && sed -i 's/^import collectsub_pb2 as/from . import collectsub_pb2 as/' \
        /app/src/zta_operator/_grpc/collectsub_pb2_grpc.py

ENV PYTHONPATH=/app/src

CMD ["kopf", "run", "--all-namespaces", "-m", "zta_operator.operator"]
