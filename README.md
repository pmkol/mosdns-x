# Mosdns-x

Mosdns-x is a high-performance DNS forwarder written in Go. It supports running a plugin pipeline, allowing users to customize DNS processing logic as needed.

It supports listening for and handling DNS queries over:
- UDP
- TCP
- DNS over TLS (DoT)
- DNS over QUIC (DoQ)
- DNS over HTTP/2 (DoH)
- DNS over HTTP/3 (DoH3)

For a feature overview, configuration guide, and tutorials, please refer to the wiki.

This branch is used for production servers and differs slightly from the description in the wiki.

Build the project on Linux using the instructions below. Ensure Go 1.25 or later is installed.
```
GOOS=linux GOARCH=amd64 GOAMD64=v3 CGO_ENABLED=0 GOEXPERIMENT=greenteagc go build -ldflags "-s -w -buildid=" -trimpath -o mosdns
```
