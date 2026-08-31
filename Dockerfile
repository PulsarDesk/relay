# Self-hosted Pulsar relay. Build:
#   docker build -t pulsar-relay .
# Run (UDP!):
#   docker run -d --name pulsar-relay -p 21116:21116/udp pulsar-relay
# With limits:
#   docker run -d -p 21116:21116/udp pulsar-relay --session-rate 10mbit
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/pulsar-relay /pulsar-relay
USER 65534:65534
EXPOSE 21116/udp
ENTRYPOINT ["/pulsar-relay"]
