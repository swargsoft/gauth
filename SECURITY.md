# Security model

## What changed from the Node prototype

- **No client secret, ever.** gauth registers as a Google "Desktop app"
  OAuth client and authenticates the token exchange with PKCE
  (code_verifier) instead. There's no secret to protect because there
  never is one — see `core/oauth.go`.
- **API key is optional, passed as a flag** (`-key`), not baked into the
  binary and not auto-generated. Empty (the default) means no auth on
  the protected endpoints. This mirrors wa-engine's `-key` flag exactly.
  You're expected to set this in `install.sh` / `install.ps1` before
  distributing them if you want it enforced.
- **No reverse proxy, no hosts-file changes.** gauth binds to
  `127.0.0.1:<port>` only. Nothing touches port 80 or `/etc/hosts`.

## CORS allowlist

`Access-Control-Allow-Origin` is only ever set for:
- `https://msgly.swargsoft.com` (exact match), and
- any scheme/port of `localhost` or `127.0.0.1` (for local frontend dev).

It is never `*`. This matters more than usual here specifically because
`-key` is optional: when no API key is configured, CORS is the only
thing stopping a page on some other origin from reading a response back
(it can still cause a blind request to be sent — that's an unavoidable
browser property, not something CORS can prevent — but it can't read
the `state`/`authUrl` needed to complete an OAuth hijack without landing
inside the allowlist).

## What running with no `-key` actually exposes

Be clear-eyed about this trade-off if you ship without `-key`:

- **Any other locally-installed program** (not just a browser) can call
  `127.0.0.1:<port>/api/google-auth/token?userId=<anything>` directly
  and mint a live Drive access token for whatever account is stored
  under that `userId`, and can call `auth-url` to link its own Google
  account under a `userId` it guesses or already knows. This requires
  the attacker to already have code execution as the same OS user —
  at which point they can also read the SQLite file and the local
  master key directly, so `-key` mainly raises the bar for casual/
  accidental local abuse, not a determined local attacker. This is the
  same boundary wa-engine already accepts by defaulting `-key` to empty.
- **A malicious webpage** the user has open in a browser tab can send
  blind requests (GET/POST/DELETE) to `127.0.0.1:<port>` — the browser
  will send them regardless of CORS. It can't *read* the responses
  (blocked by the origin allowlist above), which is what stops it from
  completing an account-hijack via `auth-url` → `callback`, but it can
  still trigger side effects like `DELETE /account` (disconnects the
  user) or force refreshes (rate-limited).

Passing `-key` (and keeping it out of any browser-visible JS, only ever
sent from a trusted backend or embedded in the installer for a
same-machine caller) closes the first category almost entirely and
meaningfully raises the bar on the second.

## Secret storage

Refresh tokens are encrypted at rest with AES-256-GCM using a
machine-local master key (`<data dir>/master.key`, `0600`) — see
`core/secretstore.go`. This protects against casual inspection of the
SQLite file alone (e.g. it ending up in a backup); it is **not**
equivalent to the OS keychain (macOS Keychain, Windows DPAPI, Linux
Secret Service) — anyone with code execution as this OS user can read
both files directly. OS-keychain integration is a possible future
enhancement; the `SecretStore` type is written so a keychain-backed
implementation is a drop-in replacement.

## OAuth CSRF / PKCE

Unrelated to the API key question and unchanged in spirit from the
Node prototype: every `auth-url` call creates a random, single-use,
10-minute, server-side-verified transaction (`core/oauthstate.go`).
Google echoes the `state` back verbatim on `/callback`; gauth looks up
its hash server-side and rejects unknown, expired, or already-used
state — this is what actually prevents OAuth login CSRF, independent of
whether `-key` is set.

## Service installation

All three platforms install gauth as a **system-wide** service (root on
Linux/macOS, a real SCM service running as `LocalSystem` on Windows —
not a per-user login item), matching wa-engine's model. This means:
- `--install-service` / `--uninstall-service` require root (Linux/macOS)
  or trigger a UAC elevation prompt (Windows).
- The client ID and, if set, the API key are embedded in the generated
  systemd unit / launchd plist / `sc.exe` service command line as plain
  command-line arguments — visible to anything that can read the
  service definition or list process arguments on that machine (i.e.
  anything running as root/admin, or on Linux, potentially any local
  user via `/proc/<pid>/cmdline` unless `hidepid` is configured). The
  client ID is public and this is fine; if you set `-key`, be aware it
  is not hidden from other privileged/local processes this way — see
  "What running with no `-key` actually exposes" above for why that's
  an acceptable, already-priced-in trade-off given the local-code-
  execution threat model, not a new one this introduces.

## Reporting a vulnerability

Do not open a public GitHub issue for a security report. Contact the
maintainers directly with reproduction steps.
