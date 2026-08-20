CREATE TABLE IF NOT EXISTS google_accounts (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id        TEXT NOT NULL UNIQUE,
	email          TEXT NOT NULL,
	access_token   TEXT NOT NULL,
	refresh_token  TEXT,              -- sealed via SecretStore (AES-256-GCM)
	expires_at     INTEGER NOT NULL,  -- epoch ms
	last_used_at   INTEGER,           -- epoch ms
	created_at     INTEGER NOT NULL,  -- epoch ms
	updated_at     INTEGER NOT NULL   -- epoch ms
);

-- Single-use OAuth CSRF transactions, bound to a PKCE code_verifier.
-- The raw state token is never stored, only its SHA-256 hash.
CREATE TABLE IF NOT EXISTS oauth_transactions (
	state_hash     TEXT PRIMARY KEY,
	user_id        TEXT NOT NULL,
	code_verifier  TEXT NOT NULL,
	expires_at     INTEGER NOT NULL,  -- epoch ms
	created_at     INTEGER NOT NULL,  -- epoch ms
	used_at        INTEGER            -- epoch ms, NULL until consumed
);

CREATE INDEX IF NOT EXISTS idx_oauth_transactions_expires
	ON oauth_transactions(expires_at);
