FROM golang:1.27-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go generate ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /palisade .
# scratch has no shell to mkdir/chown with, so /data is made here.
RUN mkdir -p /rootfs/data

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /palisade /palisade
COPY --from=builder --chown=65532:65532 /rootfs/ /
ENV TMPDIR=/data
VOLUME ["/data"]
# Non-root (issue #274). :8080 needs no capability; to listen on 80/443 map
# the ports (-p 443:8443 with --listen-tls :8443) or add
# --cap-add NET_BIND_SERVICE. A volume created while the image ran as root
# needs one chown: docker run --rm -v <volume>:/data alpine chown -R 65532:65532 /data
USER 65532:65532
EXPOSE 8080
# Probes 127.0.0.1:8080; pass --url to the healthcheck subcommand if --listen changes.
HEALTHCHECK --interval=30s --timeout=6s --start-period=30s CMD ["/palisade", "healthcheck"]
ENTRYPOINT ["/palisade"]
# No cron in a container, so prune old request logs in-process.
CMD ["--db", "/data/waf.db", "--certs", "/data/certs", "--prune-interval", "24h"]
