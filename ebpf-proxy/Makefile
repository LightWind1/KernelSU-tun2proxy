GO ?= go
BPF_CC ?= clang
BPF_CPPFLAGS ?=
all:
	$(GO) build -trimpath -o build/ebpf-proxy ./cmd/ebpf-proxy
test:
	$(GO) test -race ./internal/config ./internal/upstream ./internal/relay
android:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o build/ebpf-proxy-android ./cmd/ebpf-proxy
bpf:
	mkdir -p build
	$(BPF_CC) -target bpfel -O2 -g $(BPF_CPPFLAGS) -c bpf/redirect.bpf.c -o build/redirect.bpf.o
