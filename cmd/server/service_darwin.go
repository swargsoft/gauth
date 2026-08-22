//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const (
	serviceName = "com.swargsoft.gauth"
	plistPath   = "/Library/LaunchDaemons/com.swargsoft.gauth.plist"
)

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.swargsoft.gauth</string>

    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
        <string>--port</string>
        <string>{{.Port}}</string>
        <string>--data</string>
        <string>{{.DataDir}}</string>
        <string>--client-id</string>
        <string>{{.ClientID}}</string>
        {{- if .APIKey}}
        <string>--key</string>
        <string>{{.APIKey}}</string>
        {{- end}}
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    {{- if .ClientSecret}}
    <key>EnvironmentVariables</key>
    <dict>
        <key>GAUTH_GOOGLE_CLIENT_SECRET</key>
        <string>{{.ClientSecret}}</string>
    </dict>
    {{- end}}

    <key>StandardOutPath</key>
    <string>/var/log/gauth.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/gauth.log</string>
</dict>
</plist>
`

type plistVars struct {
	BinaryPath   string
	Port         int
	DataDir      string
	ClientID     string
	APIKey       string
	ClientSecret string
}

func installService() error {
	if *flagClientID == "" {
		return fmt.Errorf("-client-id is required (pass your Google Cloud \"Desktop app\" OAuth client ID)")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("--install-service requires root (run with sudo)")
	}

	binaryPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return fmt.Errorf("cannot resolve binary path: %w", err)
	}

	dataDir := *flagData
	if dataDir == "" {
		dataDir = defaultDataDir()
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("cannot resolve data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("cannot create data dir: %w", err)
	}

	// The client secret must be supplied externally via the
	// GAUTH_GOOGLE_CLIENT_SECRET environment variable of the caller
	// (see main.go). When present it goes into the plist's
	// EnvironmentVariables — NOT into ProgramArguments, which `ps`
	// would expose. The plist is then written root-only (0600).
	clientSecret := os.Getenv("GAUTH_GOOGLE_CLIENT_SECRET")
	plistMode := os.FileMode(0644)
	if clientSecret != "" {
		plistMode = 0600
	}

	f, err := os.OpenFile(plistPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, plistMode)
	if err != nil {
		return fmt.Errorf("cannot write plist: %w", err)
	}
	defer f.Close()

	tmpl := template.Must(template.New("plist").Parse(plistTemplate))
	if err := tmpl.Execute(f, plistVars{
		BinaryPath:   binaryPath,
		Port:         *flagPort,
		DataDir:      dataDir,
		ClientID:     *flagClientID,
		APIKey:       *flagAPIKey,
		ClientSecret: clientSecret,
	}); err != nil {
		return fmt.Errorf("cannot render plist: %w", err)
	}

	_ = exec.Command("launchctl", "unload", plistPath).Run()

	if out, err := exec.Command("launchctl", "load", "-w", plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load failed: %v\n%s", err, out)
	}

	fmt.Printf("\n✓ gauth service installed and started\n")
	fmt.Printf("  Plist:   %s\n", plistPath)
	fmt.Printf("  Data:    %s\n", dataDir)
	fmt.Printf("  Port:    %d\n", *flagPort)
	fmt.Printf("  API:     http://127.0.0.1:%d\n", *flagPort)
	if *flagAPIKey != "" {
		fmt.Printf("  Auth:    API key required (X-API-Key header or ?api_key=)\n")
	} else {
		fmt.Printf("  Auth:    none (CORS allowlist only — pass -key to require an API key)\n")
	}
	fmt.Printf("  Logs:    /var/log/gauth.log\n")
	fmt.Printf("\nManage with:\n")
	fmt.Printf("  sudo launchctl stop  %s\n", serviceName)
	fmt.Printf("  sudo launchctl start %s\n", serviceName)
	fmt.Printf("  sudo ./gauth --uninstall-service\n")
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("--uninstall-service requires root (run with sudo)")
	}

	_ = exec.Command("launchctl", "unload", "-w", plistPath).Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove plist: %w", err)
	}

	fmt.Println("✓ gauth service removed")
	return nil
}
