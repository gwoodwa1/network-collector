#!/bin/sh

set -eu

release_root="${1:-dist}"
scanner="${GOVULNCHECK:-govulncheck}"

find "$release_root" -type f \( \
	-name network-collector -o -name network-collector.exe -o \
	-name xr-routing-monitor -o -name xr-routing-monitor.exe -o \
	-name junos-routing-monitor -o -name junos-routing-monitor.exe -o \
	-name routing-monitor -o -name routing-monitor.exe -o \
	-name monitor-report -o -name monitor-report.exe \
\) -print |
while IFS= read -r binary; do
	echo "=== metadata ${binary} ==="
	go version -m "$binary"
	echo "=== vulnerability scan ${binary} ==="
	"$scanner" -mode binary "$binary"
done

# The pipeline loop runs in a subshell on POSIX shells, so verify artifacts
# independently rather than relying on the loop's found variable.
if ! find "$release_root" -type f \( \
	-name network-collector -o -name network-collector.exe -o \
	-name xr-routing-monitor -o -name xr-routing-monitor.exe -o \
	-name junos-routing-monitor -o -name junos-routing-monitor.exe -o \
	-name routing-monitor -o -name routing-monitor.exe -o \
	-name monitor-report -o -name monitor-report.exe \
\) -print -quit | grep -q .; then
	echo "no release binaries found under ${release_root}" >&2
	exit 1
fi
