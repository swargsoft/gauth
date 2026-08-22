-- Per-transaction post-consent redirect target. The frontend passes its
-- own origin (e.g. http://localhost:8765 in dev) when it calls
-- /api/google-auth/auth-url; the callback redirects there after Google
-- consent so local dev lands back on the dev server instead of the
-- hardcoded production frontend origin. Empty string = use the default
-- (FrontendOrigin). Validated against an allowlist before being stored —
-- see isAllowedReturnTo in httpapi.go.
ALTER TABLE oauth_transactions ADD COLUMN return_to TEXT NOT NULL DEFAULT '';
