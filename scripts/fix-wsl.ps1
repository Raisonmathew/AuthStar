# Fix WSL/Podman Virtualization Error script

Write-Host "Checking for Administrator privileges..." -ForegroundColor Cyan
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges to enable Windows features."
    Write-Host "Please right-click on this script (or PowerShell) and select 'Run as Administrator'." -ForegroundColor Red
    exit 1
}

Write-Host "Administrator privileges confirmed." -ForegroundColor Green

Write-Host "Enabling Windows Subsystem for Linux..." -ForegroundColor Cyan
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

Write-Host "Enabling Virtual Machine Platform..." -ForegroundColor Cyan
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

Write-Host "Setting WSL default version to 2..." -ForegroundColor Cyan
wsl --set-default-version 2

Write-Host ""
Write-Host "Features enabled successfully." -ForegroundColor Green
Write-Host "IMPORTANT: YOU MUST RESTART YOUR COMPUTER NOW." -ForegroundColor Yellow
Write-Host "After restarting, run 'podman machine init' again to complete the setup." -ForegroundColor White
Write-Host ""
