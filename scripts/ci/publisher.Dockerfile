# syntax=docker/dockerfile:1.7
# Reuse the already approved Windows-lane tool images; no hosted/new runner.
FROM messense/cargo-xwin@sha256:9856b895265d4966f212228ba64802cf89337e2a2a537aa2533c1b8784cbc81b AS rust-tools
FROM node:24-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe AS publisher-tests
ENV HOME=/tmp/publisher-jobs2/home \
    CARGO_HOME=/tmp/publisher-jobs2/cargo \
    RUSTUP_HOME=/tmp/publisher-jobs2/rustup \
    CARGO_BUILD_JOBS=2 \
    PYTHONDONTWRITEBYTECODE=1 \
    GIT_TERMINAL_PROMPT=0
ENV PATH="/tmp/publisher-jobs2/cargo/bin:${PATH}"
COPY --from=rust-tools /usr/local/cargo/ /tmp/publisher-jobs2/cargo/
COPY --from=rust-tools /usr/local/rustup/ /tmp/publisher-jobs2/rustup/
# Network is available only in dependency/tool preparation, without credentials.
RUN apt-get update \
    && apt-get install --no-install-recommends -y build-essential ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 700 "$HOME" \
    && chmod 700 /tmp/publisher-jobs2 "$CARGO_HOME" "$RUSTUP_HOME"
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY host/verifier/ ./host/verifier/
RUN cargo fetch --locked --manifest-path host/verifier/Cargo.toml
ENV CARGO_NET_OFFLINE=true
COPY host/ ./host/
COPY scripts/ ./scripts/
COPY schemas/ ./schemas/
COPY channels/ ./channels/
COPY tests/ ./tests/
ARG PUBLISHER_SOURCE_SHA
ARG PUBLISHER_RUN_ID
ARG PUBLISHER_RUN_ATTEMPT
# This executes publisher regression suites, not applications or NSIS installers.
RUN --network=none set -eu; \
    npm test; \
    LAPKB_PUBLISHER_ISOLATED_CI=1 sh scripts/test-publisher.sh; \
    install -d /out; \
    printf 'publisher-source=%s\nrun=%s\nattempt=%s\nchecks=metadata schemas, verifier, synthetic publisher/client/pickup regressions\nnetwork=none during all checks\nproduct-signing-publication-native-Windows=not performed\n' \
      "$PUBLISHER_SOURCE_SHA" "$PUBLISHER_RUN_ID" "$PUBLISHER_RUN_ATTEMPT" > /out/publisher-checks.txt
FROM scratch AS ci-evidence
COPY --from=publisher-tests /out/ /
