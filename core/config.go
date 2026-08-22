package core

import "fmt"

// Compile-time constants. Everything else that varies per install
// (Google OAuth client ID, optional API key, port, data dir) comes in
// as a CLI flag — see cmd/server/main.go — so it can be baked into the
// install.sh / install.ps1 scripts without touching source or shipping
// a config file.
const (
	// DefaultPort is what install.sh / install.ps1 pass via -port unless
	// overridden. The frontend should just hardcode
	// http://127.0.0.1:8765 — no discovery, no config needed on that end.
	DefaultPort = 8765
)

// FrontendOrigin is the default post-consent redirect target (the
// production frontend's /sync-settings route) when the auth-url request
// didn't carry a returnTo.
const FrontendOrigin = "https://msgly.swargsoft.com"

// AllowedOrigins are the exact origins allowed to read CORS responses
// and to be used as post-consent redirect targets, in addition to any
// localhost/127.0.0.1 origin for local development (see core/httpapi.go).
// Never wildcarded — see SECURITY.md.
var AllowedOrigins = []string{
	"https://msgly.swargsoft.com",
	"https://stg.msgly.swargsoft.com",
	"https://stg.msgly.pages.dev",
}

// isLocalDevOrigin reports whether origin is some form of
// localhost/127.0.0.1 (any scheme, any port) — allowed for local
// frontend development regardless of the AllowedOrigins list above.
func isLocalDevOrigin(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}

// GoogleScopes are requested on every OAuth flow. These are exactly the
// scopes msgly needs: Drive appdata + file for cloud backup, and
// userinfo email/profile so the frontend can render the signed-in
// account (gauth itself only stores the email).
var GoogleScopes = []string{
	"https://www.googleapis.com/auth/drive.appdata",
	"https://www.googleapis.com/auth/drive.file",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

// GoogleRedirectURI always targets the local loopback API port.
func GoogleRedirectURI(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/api/google-auth/callback", port)
}
