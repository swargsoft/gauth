package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	googleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	googleUserinfoURL   = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleOAuth talks directly to Google's OAuth2 endpoints using only the
// standard library — no SDK. gauth registers as a public "Desktop app"
// OAuth client and authenticates the token exchange with PKCE
// (code_verifier) instead of a client secret; see
// https://developers.google.com/identity/protocols/oauth2/native-app,
// which documents client_secret as optional for this flow.
type GoogleOAuth struct {
	clientID    string
	redirectURI string
	scopes      []string
	httpClient  *http.Client
}

func NewGoogleOAuth(clientID, redirectURI string, scopes []string) *GoogleOAuth {
	return &GoogleOAuth{
		clientID:    clientID,
		redirectURI: redirectURI,
		scopes:      scopes,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GoogleOAuth) BuildAuthURL(state, codeChallenge string) string {
	q := url.Values{}
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(g.scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "consent")
	return googleAuthEndpoint + "?" + q.Encode()
}

// TokenResult is the normalized result of a successful token exchange
// or refresh.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // epoch ms
	Email        string
}

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (g *GoogleOAuth) postToken(form url.Values) (*googleTokenResponse, error) {
	resp, err := g.httpClient.PostForm(googleTokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("request to Google token endpoint failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tr googleTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || tr.Error != "" {
		return &tr, fmt.Errorf("google returned %s: %s (%s)", resp.Status, tr.Error, tr.ErrorDesc)
	}
	return &tr, nil
}

// ExchangeCode exchanges an authorization code for tokens using PKCE
// (codeVerifier) instead of a client secret.
func (g *GoogleOAuth) ExchangeCode(code, codeVerifier string) (*TokenResult, error) {
	form := url.Values{}
	form.Set("client_id", g.clientID)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", g.redirectURI)

	tr, err := g.postToken(form)
	if err != nil {
		return nil, NewError(ErrCodeTokenExchange, 400, err.Error())
	}
	if tr.RefreshToken == "" {
		return nil, NewError(ErrCodeNoRefreshToken, 400, "Google did not return a refresh token for this authorization")
	}

	email, err := g.fetchEmail(tr.AccessToken)
	if err != nil {
		return nil, NewError(ErrCodeTokenExchange, 400, "failed to fetch account email: "+err.Error())
	}

	return &TokenResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UnixMilli(),
		Email:        email,
	}, nil
}

// RefreshAccessToken exchanges a stored refresh token for a new access
// token. Distinguishes Google's invalid_grant (refresh token
// revoked/expired — needs re-auth) from transient failures.
func (g *GoogleOAuth) RefreshAccessToken(refreshToken string) (*TokenResult, error) {
	if refreshToken == "" {
		return nil, ReauthRequired("No refresh token on file")
	}

	form := url.Values{}
	form.Set("client_id", g.clientID)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")

	tr, err := g.postToken(form)
	if err != nil {
		if tr != nil && tr.Error == "invalid_grant" {
			return nil, ReauthRequired("Refresh token expired or revoked. Please re-authenticate.")
		}
		return nil, err
	}

	return &TokenResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken, // may be empty; Google doesn't always rotate it
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UnixMilli(),
	}, nil
}

func (g *GoogleOAuth) fetchEmail(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, googleUserinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo endpoint returned %s", resp.Status)
	}

	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.Email, nil
}
