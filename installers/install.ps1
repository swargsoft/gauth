# gauth installer for Windows.
#
#   irm https://<your-release-host>/gauth/install.ps1 | iex
#
# Fill in $GauthClientId (and optionally $GauthApiKey) below before
# distributing this script, or set them as environment variables
# GAUTH_CLIENT_ID / GAUTH_API_KEY before running it.

$ErrorActionPreference = 'Stop'

# ==================== fill these in before distributing ====================
$GauthClientId = if ($env:GAUTH_CLIENT_ID) { $env:GAUTH_CLIENT_ID } else { 'REPLACE_WITH_YOUR_DESKTOP_CLIENT_ID.apps.googleusercontent.com' }
$GauthApiKey   = if ($env:GAUTH_API_KEY)   { $env:GAUTH_API_KEY }   else { '' }   # optional — leave empty for no API-key auth
# =============================================================================

$Repo = if ($env:GAUTH_REPO) { $env:GAUTH_REPO } else { 'your-org/gauth' }
$Version = if ($env:GAUTH_VERSION) { $env:GAUTH_VERSION } else { 'latest' }
$InstallDir = if ($env:GAUTH_INSTALL_DIR) { $env:GAUTH_INSTALL_DIR } else { "$env:ProgramFiles\GAuth" }
$Port = if ($env:GAUTH_PORT) { $env:GAUTH_PORT } else { '8765' }

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

if ($GauthClientId -eq 'REPLACE_WITH_YOUR_DESKTOP_CLIENT_ID.apps.googleusercontent.com') {
  Fail "GAUTH_CLIENT_ID is still the placeholder — edit this script or set `$env:GAUTH_CLIENT_ID before running it."
}

# ---- 1. Detect architecture -------------------------------------------------
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$asset = "gauth-windows-$arch.exe"
Write-Step "Detected platform: windows-$arch"

# ---- 2. Resolve download URLs ------------------------------------------------
$baseUrl = if ($Version -eq 'latest') {
  "https://github.com/$Repo/releases/latest/download"
} else {
  "https://github.com/$Repo/releases/download/$Version"
}

$tmpDir = Join-Path $env:TEMP ("gauth-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  # ---- 3. Download binary + its checksum ----------------------------------
  Write-Step "Downloading $asset..."
  $binPath = Join-Path $tmpDir $asset
  Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $binPath -UseBasicParsing
  $shaPath = Join-Path $tmpDir "$asset.sha256"
  Invoke-WebRequest -Uri "$baseUrl/$asset.sha256" -OutFile $shaPath -UseBasicParsing

  # ---- 4. Verify checksum ---------------------------------------------------
  Write-Step "Verifying checksum..."
  $expected = ((Get-Content $shaPath) -split '\s+')[0]
  $actual = (Get-FileHash -Path $binPath -Algorithm SHA256).Hash.ToLower()
  if ($expected.ToLower() -ne $actual) { Fail "Checksum mismatch for $asset" }
  Write-Step "Checksum OK"

  # ---- 5. Install ------------------------------------------------------------
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  $finalPath = Join-Path $InstallDir 'gauth.exe'
  Copy-Item -Path $binPath -Destination $finalPath -Force
  Write-Step "Installed to $finalPath"

  # ---- 6. Register + start the SCM service (elevates via UAC itself) --------
  Write-Step "Registering gauth as a Windows service..."
  $installArgs = @('--install-service', '--port', $Port, '--client-id', $GauthClientId)
  if ($GauthApiKey) { $installArgs += @('--key', $GauthApiKey) }
  & $finalPath @installArgs

  # ---- 7. Verify health -------------------------------------------------------
  Write-Step "Waiting for gauth to become healthy..."
  $healthy = $false
  for ($i = 0; $i -lt 10; $i++) {
    try {
      $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health" -UseBasicParsing -TimeoutSec 2
      if ($resp.StatusCode -eq 200) { $healthy = $true; break }
    } catch { Start-Sleep -Seconds 1 }
  }

  Write-Host ""
  if ($healthy) {
    Write-Step "gauth is installed and running on http://127.0.0.1:$Port"
  } else {
    Write-Step "gauth was installed, but the health check did not respond yet."
    Write-Step "Check with: sc query GAuthService"
  }
}
finally {
  Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
