# syntax=docker/dockerfile:1

FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

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
