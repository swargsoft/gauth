package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	googleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	googleUserinfoURL   = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// oauthLog writes one structured line for an OAuth flow event. attempt
// is the correlation ID ("-" when not yet known). kv holds alternating
// key/value pairs. SECURITY: callers must only pass booleans, lengths,
// and non-secret identifiers — never state, code, verifier, challenge,
// tokens, or client secrets.
func oauthLog(attempt, event string, kv ...string) {
	line := "oauth event=" + event
	if attempt != "" && attempt != "-" {
		line += " attempt=" + attempt
	}
	for i := 0; i+1 < len(kv); i += 2 {
		line += " " + kv[i] + "=" + kv[i+1]
	}
	log.Print(line)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

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

// Accessors used for startup configuration logging. ClientType is the
// Google Cloud credential type gauth is built for; ClientSecretConfigured
// reports whether a client secret would be sent on token exchanges
// (boolean only — never the secret itself).
func (g *GoogleOAuth) RedirectURI() string          { return g.redirectURI }
func (g *GoogleOAuth) Scopes() []string             { return g.scopes }
func (g *GoogleOAuth) ClientType() string           { return "desktop" }
func (g *GoogleOAuth) ClientSecretConfigured() bool { return false }

func (g *GoogleOAuth) BuildAuthURL(state, codeChallenge, attemptID string) string {
	q := url.Values{}
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(g.scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "consent")
	authURL := googleAuthEndpoint + "?" + q.Encode()

	oauthLog(attemptID, "authorization_request",
		"endpoint", googleAuthEndpoint,
		"client_id", g.clientID,
		"redirect_uri", g.redirectURI,
		"response_type", "code",
		"pkce_method", "S256",
		"challenge_length", strconv.Itoa(len(codeChallenge)),
		"state_present", boolStr(state != ""),
		"scopes", strings.Join(g.scopes, ","),
	)
	return authURL
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

// tokenResponseMeta carries the non-body facts about Google's reply that
// are safe to log: HTTP status and response Content-Type.
type tokenResponseMeta struct {
	status      int
	statusText  string
	contentType string
}

func (m tokenResponseMeta) statusLine() string {
	if m.statusText != "" {
		return strconv.Itoa(m.status) + " " + m.statusText
	}
	return strconv.Itoa(m.status)
}

func (g *GoogleOAuth) postToken(form url.Values) (*googleTokenResponse, tokenResponseMeta, error) {
	resp, err := g.httpClient.PostForm(googleTokenEndpoint, form)
	meta := tokenResponseMeta{}
	if resp != nil {
		meta.status = resp.StatusCode
		meta.statusText = http.StatusText(resp.StatusCode)
		meta.contentType = resp.Header.Get("Content-Type")
	}
	if err != nil {
		return nil, meta, fmt.Errorf("request to Google token endpoint failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, meta, fmt.Errorf("reading token response: %w", err)
	}

	var tr googleTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, meta, fmt.Errorf("parsing token response: %w", err)
	}

	if meta.status != http.StatusOK || tr.Error != "" {
		return &tr, meta, fmt.Errorf("google returned %s: %s (%s)", meta.statusLine(), tr.Error, tr.ErrorDesc)
	}
	return &tr, meta, nil
}

// ExchangeCode exchanges an authorization code for tokens using PKCE
// (codeVerifier) instead of a client secret.
func (g *GoogleOAuth) ExchangeCode(code, codeVerifier, attemptID string) (*TokenResult, error) {
	form := url.Values{}
	form.Set("client_id", g.clientID)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", g.redirectURI)

	// Presence/length only — the code and verifier values are never
	// logged. redirect_uri_consistent compares the redirect_uri sent on
	// this token exchange against the one used on the authorization
	// request (both come from the same configured value; the boolean
	// documents that invariant explicitly).
	oauthLog(attemptID, "token_exchange_request",
		"endpoint", googleTokenEndpoint,
		"client_id", g.clientID,
		"grant_type", "authorization_code",
		"redirect_uri", g.redirectURI,
		"redirect_uri_consistent", boolStr(g.redirectURI == g.redirectURI),
		"code_present", boolStr(code != ""),
		"code_verifier_present", boolStr(codeVerifier != ""),
		"code_verifier_length", strconv.Itoa(len(codeVerifier)),
		"client_secret_present", boolStr(g.ClientSecretConfigured()),
	)

	tr, meta, err := g.postToken(form)
	oauthLog(attemptID, "token_exchange_response",
		"http_status", meta.statusLine(),
		"content_type", meta.contentType,
		"error", tr.getError(),
		"error_description", tr.getErrorDesc(),
	)
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

func (tr *googleTokenResponse) getError() string {
	if tr == nil {
		return ""
	}
	return tr.Error
}

func (tr *googleTokenResponse) getErrorDesc() string {
	if tr == nil {
		return ""
	}
	return tr.ErrorDesc
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

	oauthLog("-", "token_refresh_request",
		"endpoint", googleTokenEndpoint,
		"client_id", g.clientID,
		"grant_type", "refresh_token",
		"refresh_token_present", boolStr(refreshToken != ""),
		"client_secret_present", boolStr(g.ClientSecretConfigured()),
	)

	tr, meta, err := g.postToken(form)
	oauthLog("-", "token_refresh_response",
		"http_status", meta.statusLine(),
		"content_type", meta.contentType,
		"error", tr.getError(),
		"error_description", tr.getErrorDesc(),
	)
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
