package core

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Server wires the six Google-auth endpoints plus /api/health.
type Server struct {
	mux            *http.ServeMux
	tokens         *TokenService
	oauthState     *OAuthStateService
	google         *GoogleOAuth
	frontendOrigin string
	apiKey         string // empty = no auth, mirroring wa-engine's -key flag
	rateLimiter    *rateLimiter
}

func NewServer(tokens *TokenService, oauthState *OAuthStateService, google *GoogleOAuth, frontendOrigin, apiKey string) *Server {
	s := &Server{
		tokens:         tokens,
		oauthState:     oauthState,
		google:         google,
		frontendOrigin: frontendOrigin,
		apiKey:         apiKey,
		rateLimiter:    newRateLimiter(time.Minute, 30),
	}

	mux := http.NewServeMux()
	// /api/health is always public — no API key required, even when one
	// is configured — so installers/monitoring can check liveness
	// without holding the secret.
	mux.HandleFunc("/api/health", s.handleHealth)

	mux.HandleFunc("/api/google-auth/auth-url", s.protected(s.rateLimited(s.handleAuthURL)))
	// /callback is public — it's Google's own redirect target and can't
	// carry an API key header. It's protected by the signed, single-use
	// PKCE-bound state instead (see oauthstate.go).
	mux.HandleFunc("/api/google-auth/callback", s.rateLimited(s.handleCallback))
	mux.HandleFunc("/api/google-auth/account", s.protected(s.handleAccount))
	mux.HandleFunc("/api/google-auth/token", s.protected(s.rateLimited(s.handleToken)))
	mux.HandleFunc("/api/google-auth/refresh-token", s.protected(s.rateLimited(s.handleRefreshToken)))

	s.mux = mux
	return s
}

// Handler returns the fully wrapped handler (security headers + CORS +
// routes) ready to hand to http.Server.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.cors(s.mux))
}

// ---- middleware ----

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// isAllowedOrigin checks the exact configured frontend origin, plus any
// scheme/port of localhost or 127.0.0.1 for local development.
func isAllowedOrigin(origin, frontendOrigin string) bool {
	if origin == "" {
		return false
	}
	if origin == frontendOrigin {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return isLocalDevOrigin(u.Hostname())
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isAllowedOrigin(origin, s.frontendOrigin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// protected enforces the optional API key (header X-API-Key or query
// param api_key, mirroring wa-engine exactly). No-op when no key is
// configured.
func (s *Server) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey == "" {
			next(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if !TimingSafeEqual(key, s.apiKey) {
			jsonError(w, http.StatusUnauthorized, ErrCodeInvalidAPIKey, "Invalid or missing API key")
			return
		}
		next(w, r)
	}
}

type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string]*hitEntry
}

type hitEntry struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(window time.Duration, max int) *rateLimiter {
	rl := &rateLimiter{window: window, max: max, hits: map[string]*hitEntry{}}
	go rl.sweep()
	return rl
}

func (rl *rateLimiter) sweep() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.hits {
			if now.After(v.resetAt) {
				delete(rl.hits, k)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.hits[key]
	if !ok || now.After(e.resetAt) {
		e = &hitEntry{count: 0, resetAt: now.Add(rl.window)}
		rl.hits[key] = e
	}
	e.count++
	return e.count <= rl.max
}

func (s *Server) rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.rateLimiter.Allow(clientIP(r)) {
			jsonError(w, http.StatusTooManyRequests, ErrCodeRateLimited, "Too many requests")
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// ---- response helpers ----

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, code ErrorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"code": string(code), "message": message},
	})
}

// writeErr renders a *core.Error with its correct status/shape, or a
// generic 500 (no internal details leaked) for anything else.
func writeErr(w http.ResponseWriter, err error) {
	if e, ok := err.(*Error); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.HTTPStatus)
		body := map[string]interface{}{}
		if e.NeedsReauth {
			body["message"] = e.Message
			body["needsReauth"] = true
		} else {
			body["error"] = map[string]string{"code": string(e.Code), "message": e.Message}
		}
		_ = json.NewEncoder(w).Encode(body)
		return
	}
	log.Printf("internal error: %v", err)
	jsonError(w, http.StatusInternalServerError, ErrCodeInternal, "Something went wrong.")
}

func requireUserID(r *http.Request) (string, error) {
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		userID = r.Header.Get("X-User-Id")
	}
	if userID == "" || len(userID) > 256 {
		return "", NewError(ErrCodeBadRequest, 400, `A valid "userId" is required`)
	}
	return userID, nil
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "service": "gauth", "version": Version})
}

func (s *Server) handleAuthURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, ErrCodeBadRequest, "Use GET")
		return
	}
	userID, err := requireUserID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	start, err := s.oauthState.Create(userID, returnToFromRequest(r, s.frontendOrigin))
	if err != nil {
		writeErr(w, err)
		return
	}
	authURL := s.google.BuildAuthURL(start.State, start.CodeChallenge)
	jsonOK(w, map[string]string{"authUrl": authURL})
}

// returnToFromRequest extracts the optional ?returnTo= base URL the
// frontend wants to land on after Google consent (it must already
// include its path, e.g. https://host/sync-settings). Only the exact
// configured frontend origin or any localhost/127.0.0.1 origin is
// allowed — anything else falls back to the default frontend origin so
// gauth can never be used as an open redirect.
func returnToFromRequest(r *http.Request, frontendOrigin string) string {
	raw := strings.TrimSpace(r.URL.Query().Get("returnTo"))
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path == "" ||
		(u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	fu, err := url.Parse(frontendOrigin)
	if err != nil || fu.Host == "" {
		return ""
	}
	if !strings.EqualFold(u.Host, fu.Host) && !isLocalDevOrigin(u.Hostname()) {
		return ""
	}
	return raw
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	defaultBase := s.frontendOrigin + "/sync-settings"
	redirectErr := func(base, msg string) {
		u := base + "?auth=error&message=" + url.QueryEscape(msg)
		http.Redirect(w, r, u, http.StatusFound)
	}

	if code == "" || state == "" {
		redirectErr(defaultBase, "Missing parameters")
		return
	}

	consumed, err := s.oauthState.ValidateAndConsume(state)
	if err != nil {
		log.Printf("oauth callback rejected: %v", err)
		redirectErr(defaultBase, "Invalid or expired authentication request")
		return
	}
	base := defaultBase
	if consumed.ReturnTo != "" {
		base = strings.TrimRight(consumed.ReturnTo, "/")
	}

	tok, err := s.google.ExchangeCode(code, consumed.CodeVerifier)
	if err != nil {
		log.Printf("oauth callback exchange failed: %v", err)
		redirectErr(base, "Google authentication failed")
		return
	}

	if _, err := s.tokens.StoreAccount(consumed.UserID, tok); err != nil {
		log.Printf("oauth callback store failed: %v", err)
		redirectErr(base, "Failed to save Google account")
		return
	}

	u := base + "?auth=success&email=" + url.QueryEscape(tok.Email)
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := requireUserID(r)
	if err != nil {
		writeErr(w, err)
		return
	}

	switch r.Method {
	case http.MethodGet:
		view, err := s.tokens.GetAccount(userID)
		if err != nil {
			writeErr(w, err)
			return
		}
		jsonOK(w, view)

	case http.MethodDelete:
		email, err := s.tokens.RemoveAccount(userID)
		if err != nil {
			writeErr(w, err)
			return
		}
		deleteFromDrive := r.URL.Query().Get("deleteFromDrive") == "true"
		resp := map[string]interface{}{
			"message": "Google account removed successfully",
			"email":   email,
		}
		if deleteFromDrive {
			// gauth is standalone and doesn't embed msgly's Drive-folder
			// logic — this is a documented no-op, not a silent pretend.
			resp["driveDeletion"] = map[string]interface{}{
				"requested":  true,
				"wasHandled": false,
				"reason":     "Drive deletion is not implemented in this gauth deployment.",
			}
		} else {
			resp["driveDeletion"] = map[string]interface{}{"requested": false}
		}
		jsonOK(w, resp)

	default:
		jsonError(w, http.StatusMethodNotAllowed, ErrCodeBadRequest, "Use GET or DELETE")
	}
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, ErrCodeBadRequest, "Use GET")
		return
	}
	userID, err := requireUserID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.tokens.GetValidToken(userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	jsonOK(w, result)
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, ErrCodeBadRequest, "Use POST")
		return
	}
	userID, err := requireUserID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := s.tokens.RefreshAccessToken(userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	jsonOK(w, result)
}
