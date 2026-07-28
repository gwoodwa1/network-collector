# syntax=docker/dockerfile:1

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

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
