FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY workers/policy-proof .
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    CARGO_BUILD_JOBS=4 cargo build --release --locked && cp target/release/passport-policy-proof /worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /worker /usr/local/bin/worker
USER 1000:1000
EXPOSE 8090
ENTRYPOINT ["worker"]
