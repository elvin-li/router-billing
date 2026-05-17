# Dockerfile for local dev + integration testing.
#
# This is NOT the production deploy path — production is an .ipk on the
# OpenWrt router. This image is useful for:
#   - running `go test ./...` in a clean Linux env (avoids the macOS
#     LC_UUID dyld quirk that bites on certain darwin builds)
#   - smoke-testing the HTTP server end-to-end on a laptop
#   - giving contributors a one-command "it boots" check
#
# Usage:
#   docker build -t router-billing .
#   docker run --rm -p 8080:8080 router-billing --check-config -config /app/config.example.yaml
#
# Or via docker-compose for a runnable instance with a persistent DB:
#   docker compose up

FROM golang:1.22-alpine AS build

WORKDIR /src

# Cache deps separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binary; no cgo means no glibc dep in the runtime image.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=docker" \
    -o /out/router-billing ./cmd/router-billing

# ---- runtime ----
FROM alpine:3.20

RUN apk add --no-cache nftables iproute2 ca-certificates tzdata && \
    addgroup -S rb && adduser -S -G rb rb

WORKDIR /app
COPY --from=build /out/router-billing /usr/local/bin/router-billing
COPY web /app/web
COPY config.example.yaml /app/config.example.yaml

# Volumes for state.
RUN mkdir -p /var/lib/router-billing /etc/router-billing && \
    chown -R rb:rb /var/lib/router-billing /etc/router-billing
VOLUME ["/var/lib/router-billing", "/etc/router-billing"]

EXPOSE 8080

# nftables needs CAP_NET_ADMIN, so when actually exercising firewall ops
# users must `docker run --cap-add=NET_ADMIN`. For test runs (no real fw)
# pass --dry-firewall.
USER rb
ENTRYPOINT ["/usr/local/bin/router-billing"]
CMD ["-config", "/etc/router-billing/config.yaml"]
