# syntax=docker/dockerfile:1

FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build

ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-X main.version=${VERSION}" \
    -o /out/network-collector \
    ./cmd/network-collector

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS runtime

RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates openssh-client tzdata \
    && addgroup -S network-collector \
    && adduser -S -G network-collector -h /workspace network-collector \
    && mkdir -p /workspace/artifacts /workspace/session_logs \
    && chown -R network-collector:network-collector /workspace

COPY --from=build /out/network-collector /usr/local/bin/network-collector
COPY --chown=network-collector:network-collector config.yaml inventory.yaml parsers.yaml /workspace/
COPY --chown=network-collector:network-collector parser_templates /workspace/parser_templates

USER network-collector:network-collector
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/network-collector"]
