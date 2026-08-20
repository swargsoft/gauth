package core

import "time"

// TokenService orchestrates account storage and keeping the access
// token fresh — the standalone equivalent of the original
// google.auth.service.js, minus anything Mongo/msgly-specific.
type TokenService struct {
	accounts    *AccountRepo
	secrets     *SecretStore
	google      *GoogleOAuth
	refreshSkew time.Duration
}

func NewTokenService(accounts *AccountRepo, secrets *SecretStore, google *GoogleOAuth, refreshSkew time.Duration) *TokenService {
	return &TokenService{accounts: accounts, secrets: secrets, google: google, refreshSkew: refreshSkew}
}

// AccountView is the safe, public view of a connected account — never
// includes tokens.
type AccountView struct {
	Email      string `json:"email"`
	ExpiresAt  string `json:"expiresAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

func toISO(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func accountToView(a *GoogleAccount) *AccountView {
	v := &AccountView{Email: a.Email, ExpiresAt: toISO(a.ExpiresAt)}
	if a.LastUsedAt.Valid {
		v.LastUsedAt = toISO(a.LastUsedAt.Int64)
	}
	return v
}

// StoreAccount persists a newly-authorized account, replacing any prior
// one for this user (one Google account per userID).
func (s *TokenService) StoreAccount(userID string, tok *TokenResult) (*AccountView, error) {
	sealedRT, err := s.secrets.Seal(tok.RefreshToken)
	if err != nil {
		return nil, err
	}
	row, err := s.accounts.Upsert(userID, tok.Email, tok.AccessToken, &sealedRT, tok.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return accountToView(row), nil
}

func (s *TokenService) GetAccount(userID string) (*AccountView, error) {
	row, err := s.accounts.FindByUserID(userID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, NewError(ErrCodeNotFound, 404, "No Google account connected")
	}
	return accountToView(row), nil
}

// ValidTokenResult is the response shape for GET /token.
type ValidTokenResult struct {
	AccessToken string `json:"accessToken"`
	Email       string `json:"email"`
	ExpiresAt   string `json:"expiresAt"`
}

// GetValidToken returns a valid access token, transparently refreshing
// it if it's expired or within the configured skew window. This is the
// one call the frontend should need for everyday use.
func (s *TokenService) GetValidToken(userID string) (*ValidTokenResult, error) {
	row, err := s.accounts.FindByUserID(userID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ReauthRequired("Ask the frontend to connect a Google account first.")
	}

	soon := time.Now().Add(s.refreshSkew).UnixMilli()
	if row.ExpiresAt <= soon {
		refreshed, err := s.refresh(row)
		if err != nil {
			return nil, err
		}
		return &ValidTokenResult{AccessToken: refreshed.AccessToken, Email: row.Email, ExpiresAt: toISO(refreshed.ExpiresAt)}, nil
	}

	_ = s.accounts.TouchLastUsed(userID)
	return &ValidTokenResult{AccessToken: row.AccessToken, Email: row.Email, ExpiresAt: toISO(row.ExpiresAt)}, nil
}

// RefreshResult is the response shape for POST /refresh-token.
type RefreshResult struct {
	AccessToken string `json:"accessToken"`
	ExpiresAt   string `json:"expiresAt"`
}

// RefreshAccessToken forces a refresh regardless of current expiry.
func (s *TokenService) RefreshAccessToken(userID string) (*RefreshResult, error) {
	row, err := s.accounts.FindByUserID(userID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ReauthRequired("No Google account connected.")
	}
	refreshed, err := s.refresh(row)
	if err != nil {
		return nil, err
	}
	return &RefreshResult{AccessToken: refreshed.AccessToken, ExpiresAt: toISO(refreshed.ExpiresAt)}, nil
}

func (s *TokenService) refresh(row *GoogleAccount) (*GoogleAccount, error) {
	if !row.RefreshToken.Valid || row.RefreshToken.String == "" {
		return nil, ReauthRequired("No refresh token on file. Please re-authenticate.")
	}
	refreshToken, err := s.secrets.Open(row.RefreshToken.String)
	if err != nil {
		return nil, err
	}

	result, err := s.google.RefreshAccessToken(refreshToken)
	if err != nil {
		return nil, err
	}

	var newRT *string
	if result.RefreshToken != "" {
		sealed, err := s.secrets.Seal(result.RefreshToken)
		if err != nil {
			return nil, err
		}
		newRT = &sealed
	}

	return s.accounts.UpdateTokens(row.UserID, result.AccessToken, newRT, result.ExpiresAt)
}

// RemoveAccount deletes the local account record and returns the email
// that was removed (for the response message).
func (s *TokenService) RemoveAccount(userID string) (string, error) {
	row, err := s.accounts.FindByUserID(userID)
	if err != nil {
		return "", err
	}
	if row == nil {
		return "", NewError(ErrCodeNotFound, 404, "No Google account connected")
	}
	if _, err := s.accounts.Delete(userID); err != nil {
		return "", err
	}
	return row.Email, nil
}
