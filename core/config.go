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

// FrontendOrigin is the msgly origin allowed to read CORS responses
// (see core/httpapi.go — localhost/127.0.0.1 are separately allowed for
// local development). Never wildcarded — see SECURITY.md.
const FrontendOrigin = "https://msgly.swargsoft.com"

// isLocalDevOrigin reports whether origin is some form of
// localhost/127.0.0.1 (any scheme, any port) — allowed for local
// frontend development regardless of the AllowedOrigins list above.
func isLocalDevOrigin(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}

// GoogleScopes are requested on every OAuth flow. All three are
// user-owned data the user explicitly consents to.
var GoogleScopes = []string{
	"https://www.googleapis.com/auth/drive.file",
	"https://www.googleapis.com/auth/drive.metadata.readonly",
	"https://www.googleapis.com/auth/userinfo.email",
}

// GoogleRedirectURI always targets the local loopback API port.
func GoogleRedirectURI(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/api/google-auth/callback", port)
}
