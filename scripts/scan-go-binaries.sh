#!/bin/sh

set -eu

expected_go_version="${EXPECTED_GO_VERSION:-go1.26.6}"
scanner="${GOVULNCHECK:-govulncheck}"
scan_root="${1:-}"
temporary_root=""

if [ "$(go env GOVERSION)" != "$expected_go_version" ]; then
	echo "expected ${expected_go_version}, got $(go env GOVERSION)" >&2
	exit 1
fi

if [ -z "$scan_root" ]; then
	temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/network-collector-security-scan.XXXXXX")"
	scan_root="$temporary_root"
fi

cleanup() {
	if [ -n "$temporary_root" ] && [ -d "$temporary_root" ]; then
		rm -rf "$temporary_root"
	fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$scan_root"

go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./cmd/... |
while IFS= read -r package; do
	if [ -z "$package" ]; then
		continue
	fi
	name="$(basename "$package")"
	binary="$scan_root/$name"
	echo "=== build ${package} ==="
	go build -trimpath -o "$binary" "$package"
	echo "=== metadata ${binary} ==="
	go version -m "$binary"
	echo "=== vulnerability scan ${binary} ==="
	"$scanner" -mode binary "$binary"
done
