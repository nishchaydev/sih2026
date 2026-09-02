# PS-26149 Setup Script
# Run this in PowerShell as Administrator

param(
    [switch]$BuildOnly,
    [switch]$Run
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  PS-26149 Secure Drive Eraser — Setup      ║" -ForegroundColor Cyan
Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [!] This tool requires Administrator privileges for raw disk I/O." -ForegroundColor Red
    Write-Host "  [!] Please re-run this script as Administrator." -ForegroundColor Red
    Write-Host ""
    exit 1
}
Write-Host "  [+] Administrator privileges confirmed" -ForegroundColor Green

# Check Rust toolchain
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustc) {
    Write-Host "  [!] Rust toolchain not found." -ForegroundColor Red
    Write-Host "  [>] Installing via rustup..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "$env:TEMP\rustup-init.exe"
    Start-Process -FilePath "$env:TEMP\rustup-init.exe" -ArgumentList "-y" -Wait
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Host "  [+] Rust installed successfully" -ForegroundColor Green
} else {
    $rustVersion = (rustc --version) -replace "rustc ", ""
    Write-Host "  [+] Rust $rustVersion found" -ForegroundColor Green
}

# Build
Write-Host ""
Write-Host "  [>] Building release binary..." -ForegroundColor Cyan
Push-Location "$PSScriptRoot\ps149"
try {
    cargo build --release 2>&1 | ForEach-Object {
        if ($_ -match "error") { Write-Host "  $_" -ForegroundColor Red }
        elseif ($_ -match "warning") { Write-Host "  $_" -ForegroundColor Yellow }
        elseif ($_ -match "Compiling|Finished") { Write-Host "  $_" -ForegroundColor Green }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Build failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

$exePath = "$PSScriptRoot\ps149\target\release\ps149.exe"
$exeSize = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
Write-Host "  [+] Build successful: ps149.exe ($exeSize MB)" -ForegroundColor Green

if ($BuildOnly) {
    Write-Host ""
    Write-Host "  Binary location: $exePath" -ForegroundColor White
    Write-Host "  To run: .\ps149\target\release\ps149.exe" -ForegroundColor White
    Write-Host ""
    exit 0
}

# Optional: set Groq API key for AI features
if (-not $env:GROQ_API_KEY) {
    Write-Host ""
    Write-Host "  [?] AI features are disabled. Set GROQ_API_KEY to enable." -ForegroundColor Yellow
    Write-Host "      `$env:GROQ_API_KEY = 'gsk_your_key_here'" -ForegroundColor DarkGray
}

# Run
if ($Run -or (-not $BuildOnly)) {
    Write-Host ""
    Write-Host "  [>] Launching PS-26149..." -ForegroundColor Cyan
    Write-Host ""
    & $exePath
}
