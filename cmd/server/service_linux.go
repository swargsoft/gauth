//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const unitPath = "/etc/systemd/system/gauth.service"

const unitTemplate = `[Unit]
Description=gauth - local Google OAuth token service for msgly.swargsoft.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} --port {{.Port}} --data {{.DataDir}} --client-id {{.ClientID}}{{if .APIKey}} --key {{.APIKey}}{{end}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

type unitVars struct {
	BinaryPath string
	Port       int
	DataDir    string
	ClientID   string
	APIKey     string
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

	f, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot write unit file: %w", err)
	}
	defer f.Close()

	tmpl := template.Must(template.New("unit").Parse(unitTemplate))
	if err := tmpl.Execute(f, unitVars{
		BinaryPath: binaryPath,
		Port:       *flagPort,
		DataDir:    dataDir,
		ClientID:   *flagClientID,
		APIKey:     *flagAPIKey,
	}); err != nil {
		return fmt.Errorf("cannot render unit file: %w", err)
	}

	mustRun := func(args ...string) error {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %v\n%s", args, err, out)
		}
		return nil
	}

	if err := mustRun("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := mustRun("systemctl", "enable", "gauth"); err != nil {
		return err
	}
	if err := mustRun("systemctl", "start", "gauth"); err != nil {
		return err
	}

	fmt.Printf("\n✓ gauth service installed and started\n")
	fmt.Printf("  Unit:    %s\n", unitPath)
	fmt.Printf("  Data:    %s\n", dataDir)
	fmt.Printf("  Port:    %d\n", *flagPort)
	fmt.Printf("  API:     http://127.0.0.1:%d\n", *flagPort)
	if *flagAPIKey != "" {
		fmt.Printf("  Auth:    API key required (X-API-Key header or ?api_key=)\n")
	} else {
		fmt.Printf("  Auth:    none (CORS allowlist only — pass -key to require an API key)\n")
	}
	fmt.Printf("\nManage with:\n")
	fmt.Printf("  sudo systemctl status gauth\n")
	fmt.Printf("  sudo systemctl stop   gauth\n")
	fmt.Printf("  sudo systemctl start  gauth\n")
	fmt.Printf("  journalctl -u gauth -f\n")
	fmt.Printf("  sudo ./gauth --uninstall-service\n")
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("--uninstall-service requires root (run with sudo)")
	}

	_ = exec.Command("systemctl", "stop", "gauth").Run()
	_ = exec.Command("systemctl", "disable", "gauth").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("✓ gauth service removed")
	return nil
}
