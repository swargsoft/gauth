package core

import (
	"database/sql"
	"time"
)

// GoogleAccount is a row from google_accounts. RefreshToken holds the
// SecretStore-sealed ciphertext, never the raw token.
type GoogleAccount struct {
	UserID       string
	Email        string
	AccessToken  string
	RefreshToken sql.NullString
	ExpiresAt    int64
	LastUsedAt   sql.NullInt64
	CreatedAt    int64
	UpdatedAt    int64
}

type AccountRepo struct{ db *sql.DB }

func NewAccountRepo(db *sql.DB) *AccountRepo { return &AccountRepo{db: db} }

func (r *AccountRepo) FindByUserID(userID string) (*GoogleAccount, error) {
	row := r.db.QueryRow(`SELECT user_id, email, access_token, refresh_token, expires_at, last_used_at, created_at, updated_at
		FROM google_accounts WHERE user_id = ?`, userID)
	var a GoogleAccount
	if err := row.Scan(&a.UserID, &a.Email, &a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.LastUsedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// coalesceRefreshToken keeps the existing sealed refresh token when a
// new one isn't supplied (Google doesn't always rotate it on refresh).
func coalesceRefreshToken(existing *GoogleAccount, newToken *string) interface{} {
	if newToken != nil {
		return *newToken
	}
	if existing != nil && existing.RefreshToken.Valid {
		return existing.RefreshToken.String
	}
	return nil
}

// Upsert inserts or fully replaces the single account for this user
// (one Google account per user_id, matching the reference behavior:
// reconnecting replaces the prior account).
func (r *AccountRepo) Upsert(userID, email, accessToken string, refreshToken *string, expiresAt int64) (*GoogleAccount, error) {
	existing, err := r.FindByUserID(userID)
	if err != nil {
		return nil, err
	}
	rt := coalesceRefreshToken(existing, refreshToken)
	now := time.Now().UnixMilli()

	if existing != nil {
		_, err = r.db.Exec(`UPDATE google_accounts SET email=?, access_token=?, refresh_token=?, expires_at=?, last_used_at=?, updated_at=? WHERE user_id=?`,
			email, accessToken, rt, expiresAt, now, now, userID)
	} else {
		_, err = r.db.Exec(`INSERT INTO google_accounts (user_id, email, access_token, refresh_token, expires_at, last_used_at, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?)`, userID, email, accessToken, rt, expiresAt, now, now, now)
	}
	if err != nil {
		return nil, err
	}
	return r.FindByUserID(userID)
}

func (r *AccountRepo) UpdateTokens(userID, accessToken string, refreshToken *string, expiresAt int64) (*GoogleAccount, error) {
	existing, err := r.FindByUserID(userID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}
	rt := coalesceRefreshToken(existing, refreshToken)
	now := time.Now().UnixMilli()

	if _, err := r.db.Exec(`UPDATE google_accounts SET access_token=?, refresh_token=?, expires_at=?, last_used_at=?, updated_at=? WHERE user_id=?`,
		accessToken, rt, expiresAt, now, now, userID); err != nil {
		return nil, err
	}
	return r.FindByUserID(userID)
}

func (r *AccountRepo) TouchLastUsed(userID string) error {
	_, err := r.db.Exec(`UPDATE google_accounts SET last_used_at=? WHERE user_id=?`, time.Now().UnixMilli(), userID)
	return err
}

func (r *AccountRepo) Delete(userID string) (bool, error) {
	res, err := r.db.Exec(`DELETE FROM google_accounts WHERE user_id=?`, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
