GO ?= go
all:
	$(GO) build -trimpath -o build/ebpf-proxy ./cmd/ebpf-proxy
test:
	$(GO) test -race ./internal/config ./internal/upstream ./internal/relay
android:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o build/ebpf-proxy-android ./cmd/ebpf-proxy
