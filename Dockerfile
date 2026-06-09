# Multi-stage build producing a tiny static image with both binaries.
#   docker build -t aggershield .
#   docker run -p 8080:8080 -v "$PWD/config.json:/config.json" aggershield   # agent
#   docker run -p 9000:9000 --entrypoint /usr/local/bin/aggershield-server \
#       -e AGGERSHIELD_ADMIN_TOKEN=... aggershield                            # control plane
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/aggershield ./cmd/aggershield && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/aggershield-server ./cmd/aggershield-server

# Distroless static: no shell, no package manager — minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aggershield /usr/local/bin/aggershield
COPY --from=build /out/aggershield-server /usr/local/bin/aggershield-server
EXPOSE 8080 9000
ENTRYPOINT ["/usr/local/bin/aggershield"]
CMD ["-config", "/config.json"]
