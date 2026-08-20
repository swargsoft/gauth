# gauth Makefile
# Usage:
#   make mac              - build server binary for macOS (current arch)
#   make linux            - cross-compile for linux/amd64
#   make windows          - cross-compile for windows/amd64
#   make run              - build + run locally on port 8765 (no API key)
#   make run-secure       - build + run locally with an API key
#   make install-service  - install as a system service (requires sudo)
#   make sha256sums       - checksum every build/gauth* artifact
#   make clean            - remove build artifacts

MODULE     := github.com/swargsoft/gauth
OUT_DIR    := ./build
DATA_DIR   := ./gauth-data
VERSION    ?= dev
LD_FLAGS   := -ldflags="-s -w -X $(MODULE)/core.Version=$(VERSION)"

# Fill in for local `make run` / `make run-secure` testing.
CLIENT_ID  ?= REPLACE_WITH_YOUR_DESKTOP_CLIENT_ID.apps.googleusercontent.com
API_KEY    ?= dev-local-key

.PHONY: all mac linux windows run run-secure install-service uninstall-service sha256sums clean tidy vet fmt

all: mac

# ─── Desktop / Server builds ──────────────────────────────────────────────

mac:
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=1 go build $(LD_FLAGS) -o $(OUT_DIR)/gauth ./cmd/server
	@echo "✓ Built $(OUT_DIR)/gauth (macOS)"

linux:
	@mkdir -p $(OUT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	  CC=x86_64-linux-musl-gcc \
	  go build $(LD_FLAGS) -o $(OUT_DIR)/gauth-linux ./cmd/server
	@echo "✓ Built $(OUT_DIR)/gauth-linux"

# Windows cross-compile requires mingw: brew install mingw-w64
windows:
	@mkdir -p $(OUT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
	  CC=x86_64-w64-mingw32-gcc \
	  go build $(LD_FLAGS) -o $(OUT_DIR)/gauth.exe ./cmd/server
	@echo "✓ Built $(OUT_DIR)/gauth.exe"

# ─── Local run ──────────────────────────────────────────────────────────

run: mac
	$(OUT_DIR)/gauth --port 8765 --data $(DATA_DIR) --client-id $(CLIENT_ID)

run-secure: mac
	$(OUT_DIR)/gauth --port 8765 --data $(DATA_DIR) --client-id $(CLIENT_ID) --key $(API_KEY)

install-service: mac
	sudo $(OUT_DIR)/gauth --install-service --port 8765 --client-id $(CLIENT_ID)

uninstall-service:
	sudo $(OUT_DIR)/gauth --uninstall-service

# ─── Smoke test (requires running server + jq) ───────────────────────────

smoke-test:
	@echo "=== Health check ==="
	curl -s http://127.0.0.1:8765/api/health | jq .
	@echo "\n=== Get auth URL (requires a real connected userId to go further) ==="
	curl -s "http://127.0.0.1:8765/api/google-auth/auth-url?userId=test-user" | jq .

# ─── Checksums ─────────────────────────────────────────────────────────

sha256sums:
	@for f in $(OUT_DIR)/gauth*; do \
	  [ -f "$$f" ] && sha256sum "$$f" > "$$f.sha256"; \
	done
	@echo "✓ Generated per-artifact .sha256 files in $(OUT_DIR)"

clean:
	rm -rf $(OUT_DIR)

tidy:
	go mod tidy

vet:
	go vet ./...

fmt:
	gofmt -w .
