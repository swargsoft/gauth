package core

import (
	"database/sql"
	"time"
)

type oauthTxnRepo struct{ db *sql.DB }

func newOAuthTxnRepo(db *sql.DB) *oauthTxnRepo { return &oauthTxnRepo{db: db} }

func (r *oauthTxnRepo) create(stateHash, userID, codeVerifier, returnTo, attemptID string, expiresAt int64) error {
	_, err := r.db.Exec(`INSERT INTO oauth_transactions (state_hash, user_id, code_verifier, return_to, attempt_id, expires_at, created_at, used_at)
		VALUES (?,?,?,?,?,?,?,NULL)`, stateHash, userID, codeVerifier, returnTo, attemptID, expiresAt, time.Now().UnixMilli())
	return err
}

type oauthTxn struct {
	UserID       string
	CodeVerifier string
	ReturnTo     string
	AttemptID    string
	ExpiresAt    int64
	UsedAt       sql.NullInt64
}

func (r *oauthTxnRepo) find(stateHash string) (*oauthTxn, error) {
	row := r.db.QueryRow(`SELECT user_id, code_verifier, return_to, attempt_id, expires_at, used_at FROM oauth_transactions WHERE state_hash=?`, stateHash)
	var t oauthTxn
	if err := row.Scan(&t.UserID, &t.CodeVerifier, &t.ReturnTo, &t.AttemptID, &t.ExpiresAt, &t.UsedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// consume marks a transaction used, but only if it is still unused.
// Returns true iff this call is the one that consumed it — guards
// against a replay/race on the same state token.
func (r *oauthTxnRepo) consume(stateHash string) (bool, error) {
	res, err := r.db.Exec(`UPDATE oauth_transactions SET used_at=? WHERE state_hash=? AND used_at IS NULL`,
		time.Now().UnixMilli(), stateHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (r *oauthTxnRepo) deleteExpired() (int64, error) {
	res, err := r.db.Exec(`DELETE FROM oauth_transactions WHERE expires_at < ?`, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// OAuthStateService issues and validates signed, single-use OAuth
// transactions. Google echoes `state` back verbatim on the callback; we
// look up its hash server-side and never trust anything the client
// claims about it — this is what prevents OAuth login CSRF and
// cross-user account binding.
//
// Each transaction also carries a PKCE code_verifier/code_challenge pair
// (RFC 7636): the challenge goes out in the auth URL, the verifier is
// held here server-side until the callback needs it for the token
// exchange — gauth has no client secret to authenticate with instead
// (see core/oauth.go).
type OAuthStateService struct {
	repo *oauthTxnRepo
	ttl  time.Duration
}

func NewOAuthStateService(db *sql.DB, ttl time.Duration) *OAuthStateService {
	return &OAuthStateService{repo: newOAuthTxnRepo(db), ttl: ttl}
}

type OAuthStartResult struct {
	State         string
	CodeChallenge string
	AttemptID     string
}

func (s *OAuthStateService) Create(userID, returnTo string) (*OAuthStartResult, error) {
	state := GenerateState()
	stateHash := SHA256Hex(state)
	verifier := GenerateCodeVerifier()
	challenge := CodeChallengeS256(verifier)
	attemptID := GenerateAttemptID()
	expiresAt := time.Now().Add(s.ttl).UnixMilli()

	if err := s.repo.create(stateHash, userID, verifier, returnTo, attemptID, expiresAt); err != nil {
		return nil, err
	}
	return &OAuthStartResult{State: state, CodeChallenge: challenge, AttemptID: attemptID}, nil
}

type OAuthConsumeResult struct {
	UserID       string
	CodeVerifier string
	ReturnTo     string // validated post-consent redirect base, empty = default frontend origin
	AttemptID    string
}

func (s *OAuthStateService) ValidateAndConsume(state string) (*OAuthConsumeResult, error) {
	if state == "" {
		return nil, NewError(ErrCodeInvalidState, 400, "Missing or invalid state parameter")
	}
	stateHash := SHA256Hex(state)

	txn, err := s.repo.find(stateHash)
	if err != nil {
		return nil, err
	}
	if txn == nil {
		return nil, NewError(ErrCodeInvalidState, 400, "Unknown OAuth state")
	}
	if txn.UsedAt.Valid {
		return nil, NewError(ErrCodeStateReplayed, 400, "OAuth state has already been used")
	}
	if txn.ExpiresAt < time.Now().UnixMilli() {
		return nil, NewError(ErrCodeStateExpired, 400, "OAuth state has expired")
	}

	consumed, err := s.repo.consume(stateHash)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, NewError(ErrCodeStateReplayed, 400, "OAuth state has already been used")
	}

	return &OAuthConsumeResult{UserID: txn.UserID, CodeVerifier: txn.CodeVerifier, ReturnTo: txn.ReturnTo, AttemptID: txn.AttemptID}, nil
}

func (s *OAuthStateService) CleanupExpired() (int64, error) {
	return s.repo.deleteExpired()
}
