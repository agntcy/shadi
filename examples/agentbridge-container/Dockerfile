# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# agentbridge with a fake harness (no model), for trying runtime discovery
# with containers. Build from the repository root:
#
#   docker build -f examples/agentbridge-container/Dockerfile -t agentbridge-fake .

FROM rust:1.98.1-bookworm AS build
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p agntcy-agentbridge-cli -p agntcy-shadi-cli \
 && cp target/release/agentbridge target/release/shadictl /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/agentbridge /usr/local/bin/shadictl /usr/local/bin/
COPY examples/agentbridge-container/fake-harness examples/agentbridge-container/entrypoint.sh /usr/local/bin/
COPY examples/agentbridge-container/profiles /opt/agentbridge/profiles
ENV AGENTBRIDGE_PROFILES_DIR=/opt/agentbridge/profiles
EXPOSE 8443 8081
ENTRYPOINT ["entrypoint.sh"]
