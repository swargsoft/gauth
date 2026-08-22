# gauth

A tiny, standalone, cross-platform Go service that manages Google OAuth
tokens locally on a user's machine, over a small local HTTP API, for
[msgly.swargsoft.com](https://msgly.swargsoft.com). Ships as a single
static binary — no runtime, no config file, no external dependencies on
the target machine. Built in Go to mirror `wa-engine`'s architecture:
same SQLite-via-`mattn/go-sqlite3` storage pattern, same flag-based
config, same per-OS system-service installation, same release process.

- Runs on **macOS, Windows, and Linux** as a real system service
  (systemd / LaunchDaemon / native Windows SCM service)
- **No client secret** — registers as a public Google "Desktop app"
  OAuth client and uses PKCE instead (see `core/oauth.go`)
- **No required config or API key** — Google client ID and an optional
  API key are passed as flags, meant to be baked into `install.sh` /
  `install.ps1` before you distribute them
- Talks to `127.0.0.1:<port>` only — no reverse proxy, no hosts-file
  changes, no port 80

## Architecture

```
core/
  config.go        Compile-time constants (frontend origin, default port, scopes)
  errors.go         Stable error codes + the operational Error type
  crypto.go          PKCE, state, hashing, envelope encryption, API-key comparison
  secretstore.go      AES-256-GCM envelope encryption for refresh tokens at rest
  db.go               SQLite open + embedded migration runner
  migrations/          SQL schema
  accounts.go          google_accounts data access
  oauthstate.go         oauth_transactions data access + the state/PKCE service
  oauth.go               Google OAuth2 client (stdlib only, no client secret)
  tokenservice.go          Account storage + auto-refresh orchestration
  httpapi.go                 Routes, optional API-key auth, CORS, rate limiting, handlers
cmd/server/
  main.go            Flag parsing, HTTP server bootstrap, graceful shutdown
  service_linux.go    systemd system service (root)
  service_darwin.go    launchd LaunchDaemon (root)
  service_windows.go    Real Windows SCM service (golang.org/x/sys/windows/svc), UAC elevation
  iservice_other.go      No-op Windows-service stub for non-Windows builds
installers/
  install.sh, install.ps1   Bake in client ID / API key, download + verify + install
.github/workflows/release.yml   Per-platform build + checksum + GitHub Release
Makefile
```

## Requirements to build from source

- Go 1.25+
- A C toolchain (mattn/go-sqlite3 uses cgo) — native on macOS/Linux;
  `mingw-w64` for cross-compiling to Windows, `musl-gcc` for a static
  Linux build. See the Makefile's `linux` / `windows` targets.
- Run `go mod tidy` once you have network access — `go.sum` isn't
  checked in here since this was built offline (see `go.sum.README`).

```bash
make mac
make run           # foreground, no API key, on :8765
make run-secure    # foreground, with a local dev API key
```

## Installation (end users)

Before distributing `installers/install.sh` / `install.ps1`, edit the
placeholder values near the top of each:

```bash
GAUTH_CLIENT_ID="..."   # your Google Cloud "Desktop app" OAuth client ID
GAUTH_API_KEY=""        # optional — leave empty for no API-key auth
```

(Or leave the scripts untouched and set `GAUTH_CLIENT_ID` / `GAUTH_API_KEY`
as environment variables at distribution/run time instead — both work.)

```bash
curl -fsSL https://<your-release-host>/gauth/install.sh | bash        # macOS / Linux
irm https://<your-release-host>/gauth/install.ps1 | iex                # Windows
```

Both: detect OS/architecture, download the matching release binary,
**verify its SHA256 checksum**, install it, register + start it as a
system-wide service, and verify `/api/health` responds.

### Uninstall

```bash
sudo gauth --uninstall-service      # macOS / Linux
gauth --uninstall-service           # Windows — will prompt for UAC
```

## Google Cloud OAuth setup

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
   create an OAuth 2.0 Client ID with application type **Desktop app**
   (not "Web application" — Web application clients always require a
   confidential secret at the token endpoint, which a shipped binary
   can't provide).
2. Copy the generated **Client ID** — that's the only value gauth needs.
   Google's Desktop app credentials do still include a secret in the
   Console, but the token endpoint treats it as optional for this
   client type and gauth never sends it (see `core/oauth.go`).
3. Desktop app clients accept any `http://127.0.0.1:<port>` loopback
   redirect without pre-registering an exact port (RFC 8252 §7.3), so
   changing `-port` doesn't require touching Google Cloud Console.
4. **Refresh tokens expire after 7 days while your OAuth consent screen
   is in "Testing" publishing status** — this applies regardless of
   client type. Move to "In production" and complete Google's
   verification for the requested scopes (Drive scopes are very likely
   to require it) to get genuinely long-lived tokens.

## Configuration (all via flags — no config file, no env vars required)

| Flag | Default | Notes |
|---|---|---|
| `-port` | `8765` | Frontend should hardcode `http://127.0.0.1:8765` |
| `-host` | `127.0.0.1` | Loopback only |
| `-data` | `~/.gauth` (or `%PROGRAMDATA%\GAuth` for the Windows service) | |
| `-client-id` | *(required)* | Your Google Cloud "Desktop app" OAuth client ID |
| `-key` | *(empty = no auth)* | Optional API key — see SECURITY.md for the trade-off |

## API

Base URL: `http://127.0.0.1:8765`. If `-key` was set, protected
endpoints require `X-API-Key: <key>` header or `?api_key=<key>` query
param (matches wa-engine's exact convention). `/api/health` never
requires it. `userId` is an application-level identifier your frontend
supplies (`?userId=`, or `X-User-Id` header for POST/DELETE).

### `GET /api/health` — always public
```json
{"status":"ok","service":"gauth","version":"1.0.0"}
```

### `GET /api/google-auth/auth-url?userId=<id>&returnTo=<base-url>`
Returns `{"authUrl": "https://accounts.google.com/..."}`. Redirect the
browser there; Google redirects back to `/callback` on completion.

`returnTo` is optional: a full base URL (including its path) the browser
is redirected to after consent instead of the built-in
`<frontend-origin>/sync-settings`. Only the configured production
frontend origin or any localhost/127.0.0.1 origin is honored — anything
else silently falls back to the default, so gauth can't be used as an
open redirect. This is how the msgly Vite dev server (localhost:5173)
gets its post-consent redirect.

### `GET /api/google-auth/callback` — public (Google's own redirect target)
Validates the signed PKCE-bound state, exchanges the code, stores the
account, redirects to
`<frontend>/sync-settings?auth=success&email=...` (or `auth=error`).

### `GET /api/google-auth/account?userId=<id>`
```json
{"email":"user@gmail.com","expiresAt":"...","lastUsedAt":"..."}
```
Never returns tokens.

### `GET /api/google-auth/token?userId=<id>`
Auto-refreshes if within 5 minutes of expiry.
```json
{"accessToken":"...","email":"user@gmail.com","expiresAt":"..."}
```
`401` with `{"message":"...","needsReauth":true}` if re-auth is needed.

### `POST /api/google-auth/refresh-token`
Forces a refresh regardless of current expiry.

### `DELETE /api/google-auth/account?userId=<id>&deleteFromDrive=true`
Removes the local account record. `deleteFromDrive` is accepted but is
a documented no-op (`driveDeletion.wasHandled: false`) — gauth doesn't
embed msgly's Drive-folder logic.

### Frontend example
```js
const res = await fetch('http://127.0.0.1:8765/api/google-auth/token?userId=user_123', {
  headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
});
const { accessToken, needsReauth } = await res.json();
```

## Security model

See [`SECURITY.md`](./SECURITY.md) — especially the "What running with
no `-key` actually exposes" section before deciding whether to ship
without one.

## Release process

Push a tag like `v1.0.0`. `.github/workflows/release.yml` builds
`linux-amd64`, `linux-arm64`, `mac-arm64`, `mac-amd64`, and
`windows-amd64` natively per-platform (cgo needs a matching C
toolchain per target — see wa-engine's identical reasoning), generates
a per-artifact `.sha256`, and publishes everything plus the installer
scripts to a GitHub Release.
