// cmd/server/main.go - platform-independent HTTP server for gauth
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	core "github.com/swargsoft/gauth/core"
)

var (
	flagPort      = flag.Int("port", core.DefaultPort, "HTTP API port")
	flagData      = flag.String("data", "", "Data directory (default: ~/.gauth)")
	flagHost      = flag.String("host", "127.0.0.1", "Bind address (127.0.0.1 = local only)")
	flagClientID  = flag.String("client-id", "", "Google OAuth Desktop-app client ID (required)")
	flagAPIKey    = flag.String("key", "", "Optional API key (empty = no auth)")
	flagVer       = flag.Bool("version", false, "Print version and exit")
	flagInstall   = flag.Bool("install-service", false, "Install and start gauth as a system service")
	flagUninstall = flag.Bool("uninstall-service", false, "Stop and remove the gauth system service")
)

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./gauth-data"
	}
	return filepath.Join(home, ".gauth")
}

func main() {
	// MUST happen before flag.Parse() — see wa-engine's identical
	// comment in its main.go for why (Windows SCM launch detection).
	if checkWindowsService() {
		return
	}

	flag.Parse()

	if *flagVer {
		fmt.Printf("gauth %s\n", core.Version)
		os.Exit(0)
	}

	if *flagInstall {
		if err := installService(); err != nil {
			log.Fatalf("install-service failed: %v", err)
		}
		os.Exit(0)
	}

	if *flagUninstall {
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall-service failed: %v", err)
		}
		os.Exit(0)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		<-sigCh
		close(stop)
	}()

	if err := runServer(stop); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// runServer starts the HTTP server and blocks until stop is closed.
// stop is a plain chan struct{} so it works from both the OS-signal path
// (foreground) and the Windows SCM path (service) without type gymnastics.
func runServer(stop <-chan struct{}) error {
	if *flagClientID == "" {
		return fmt.Errorf("-client-id is required (your Google Cloud \"Desktop app\" OAuth client ID)")
	}

	dataPath := *flagData
	if dataPath == "" {
		dataPath = defaultDataDir()
	}
	dataDir, err := filepath.Abs(dataPath)
	if err != nil {
		return fmt.Errorf("invalid data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("cannot create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "gauth.db")
	db, err := core.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	masterKey, err := core.LoadOrCreateMasterKey(filepath.Join(dataDir, "master.key"))
	if err != nil {
		return fmt.Errorf("failed to load master key: %w", err)
	}

	accounts := core.NewAccountRepo(db)
	secrets := core.NewSecretStore(masterKey)
	oauthState := core.NewOAuthStateService(db, 10*time.Minute)
	redirectURI := core.GoogleRedirectURI(*flagPort)
	google := core.NewGoogleOAuth(*flagClientID, redirectURI, core.GoogleScopes)
	tokens := core.NewTokenService(accounts, secrets, google, 5*time.Minute)

	srv := core.NewServer(tokens, oauthState, google, core.FrontendOrigin, *flagAPIKey)

	cleanupStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupStop:
				return
			case <-ticker.C:
				_, _ = oauthState.CleanupExpired()
			}
		}
	}()

	addr := fmt.Sprintf("%s:%d", *flagHost, *flagPort)
	httpSrv := &http.Server{
		Addr:        addr,
		Handler:     srv.Handler(),
		ReadTimeout: 30 * time.Second,
	}

	log.Printf("gauth %s listening on http://%s", core.Version, addr)
	log.Printf("Data directory: %s", dataDir)
	if *flagAPIKey != "" {
		log.Printf("API key auth enabled")
	} else {
		log.Printf("API key auth disabled (-key not set) — CORS allowlist is the only origin restriction, see SECURITY.md")
	}
	log.Printf("oauth config: client_id=%s client_type=%s redirect_uri=%s scopes=%s pkce_enabled=true pkce_method=S256 client_secret_configured=%t",
		*flagClientID,
		google.ClientType(),
		redirectURI,
		strings.Join(core.GoogleScopes, ","),
		google.ClientSecretConfigured(),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-stop:
	case err := <-errCh:
		close(cleanupStop)
		return err
	}

	log.Println("Shutting down...")
	close(cleanupStop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Println("Stopped.")
	return nil
}
