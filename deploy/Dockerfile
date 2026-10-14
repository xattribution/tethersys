# One image, two programs: tetherd and the official iroh-relay.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p tetherd \
 && cargo install --locked iroh-relay@1.3.0 --features server --root /out \
 && cp target/release/tetherd /out/bin/

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wireguard-tools iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/bin/tetherd /out/bin/iroh-relay /usr/local/bin/
ENV TETHERD_DATA=/data
VOLUME /data
EXPOSE 47711/udp
ENTRYPOINT ["tetherd"]
