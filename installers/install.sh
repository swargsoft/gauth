#!/usr/bin/env bash
# gauth installer for macOS and Linux.
#
#   curl -fsSL https://<your-release-host>/gauth/install.sh | bash
#
# Fill in GAUTH_CLIENT_ID (and optionally GAUTH_API_KEY and
# GAUTH_GOOGLE_CLIENT_SECRET) below before distributing this script —
# that's the "bake the secret into the installer, not the binary" model.
# All three also work as environment variables if you'd rather inject
# them at distribution time instead of editing this file:
#
#   GAUTH_CLIENT_ID=xxx GAUTH_API_KEY=yyy GAUTH_GOOGLE_CLIENT_SECRET=zzz bash install.sh
set -euo pipefail

# ==================== fill these in before distributing ====================
GAUTH_CLIENT_ID="${GAUTH_CLIENT_ID:-REPLACE_WITH_YOUR_DESKTOP_CLIENT_ID.apps.googleusercontent.com}"
GAUTH_API_KEY="${GAUTH_API_KEY:-}"   # optional — leave empty for no API-key auth
GAUTH_GOOGLE_CLIENT_SECRET="${GAUTH_GOOGLE_CLIENT_SECRET:-}"  # Desktop-app client_secret — REQUIRED for the token exchange, even with PKCE
# =============================================================================

REPO="${GAUTH_REPO:-your-org/gauth}"
VERSION="${GAUTH_VERSION:-latest}"
INSTALL_DIR="${GAUTH_INSTALL_DIR:-/usr/local/bin}"
PORT="${GAUTH_PORT:-8765}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

if [ "$GAUTH_CLIENT_ID" = "REPLACE_WITH_YOUR_DESKTOP_CLIENT_ID.apps.googleusercontent.com" ]; then
  fail "GAUTH_CLIENT_ID is still the placeholder — edit this script or pass GAUTH_CLIENT_ID=... in the environment."
fi

if [ -z "$GAUTH_GOOGLE_CLIENT_SECRET" ]; then
  fail "GAUTH_GOOGLE_CLIENT_SECRET is empty — Google requires the Desktop-app client_secret on every token exchange, even with PKCE. Edit this script or pass GAUTH_GOOGLE_CLIENT_SECRET=... in the environment."
fi

# ---- 1. Detect OS and architecture ----------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Darwin) platform="mac" ;;
  Linux)  platform="linux" ;;
  *) fail "Unsupported OS: $os (use install.ps1 on Windows)" ;;
esac

case "$arch" in
  x86_64|amd64)  goarch="amd64" ;;
  arm64|aarch64) goarch="arm64" ;;
  *) fail "Unsupported architecture: $arch" ;;
esac

asset="gauth-${platform}-${goarch}"
log "Detected platform: ${platform}-${goarch}"

# ---- 2. Resolve download URLs ----------------------------------------------
if [ "$VERSION" = "latest" ]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# ---- 3. Download binary + its checksum -------------------------------------
log "Downloading ${asset}..."
curl -fsSL "${base_url}/${asset}" -o "$tmp_dir/$asset" || fail "Failed to download ${asset}"
curl -fsSL "${base_url}/${asset}.sha256" -o "$tmp_dir/$asset.sha256" || fail "Failed to download checksum"

# ---- 4. Verify checksum -----------------------------------------------------
log "Verifying checksum..."
expected="$(awk '{print $1}' "$tmp_dir/$asset.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || fail "Checksum mismatch for ${asset} (expected $expected, got $actual)"
log "Checksum OK"

# ---- 5. Install --------------------------------------------------------------
sudo install -m 0755 "$tmp_dir/$asset" "$INSTALL_DIR/gauth"
log "Installed to $INSTALL_DIR/gauth"

# ---- 6. Register + start the system service (requires root) -----------------
# GAUTH_GOOGLE_CLIENT_SECRET is exported so sudo passes it through to
# --install-service, which stores it in the service's environment (never
# on the command line). On macOS the plist is written 0600 root-only
# when a secret is present.
log "Registering gauth as a system service..."
export GAUTH_GOOGLE_CLIENT_SECRET
if [ -n "$GAUTH_API_KEY" ]; then
  sudo -E "$INSTALL_DIR/gauth" --install-service --port "$PORT" --client-id "$GAUTH_CLIENT_ID" --key "$GAUTH_API_KEY"
else
  sudo -E "$INSTALL_DIR/gauth" --install-service --port "$PORT" --client-id "$GAUTH_CLIENT_ID"
fi

# ---- 7. Verify health ---------------------------------------------------------
log "Waiting for gauth to become healthy..."
healthy=0
for i in $(seq 1 10); do
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done

echo
if [ "$healthy" = "1" ]; then
  log "gauth is installed and running on http://127.0.0.1:${PORT}"
else
  log "gauth was installed, but the health check did not respond yet."
  log "Linux: sudo systemctl status gauth   |   macOS: sudo launchctl list | grep gauth"
fi
