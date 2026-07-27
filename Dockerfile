# syntax=docker/dockerfile:1

FROM golang:1.25.12-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS build

ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/network-collector \
    ./cmd/network-collector

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS runtime

RUN apk add --no-cache ca-certificates openssh-client tzdata \
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
