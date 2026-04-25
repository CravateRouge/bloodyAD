<#
.SYNOPSIS
    Stage 1 of the bloodyAD test lab bootstrap: rename the host, install
    AD Domain Services, and promote to a forest root DC for bloody.corp.

.DESCRIPTION
    Run this on a fresh Windows Server 2022/2025 VM as local Administrator.
    The machine will reboot after promotion completes. Once it comes back
    up, log in as BLOODY\Administrator with the same password and run
    setup-dc-stage2.ps1 to install AD CS.

    This script is idempotent on reruns up to the point of reboot.

.PARAMETER DomainName
    FQDN of the forest root domain. Default: bloody.corp

.PARAMETER NetbiosName
    NetBIOS name for the domain. Default: BLOODY

.PARAMETER ComputerName
    Hostname for the DC. Default: MAIN  (produces main.bloody.corp)

.PARAMETER AdminPassword
    Password for the Directory Services Restore Mode account and the
    domain Administrator. Default: Password123!  (matches
    tests/secrets.json.example - change in prod, obviously).

.EXAMPLE
    PS> .\setup-dc-stage1.ps1
    Uses defaults - produces main.bloody.corp / BLOODY\Administrator
    with password Password123!.

.NOTES
    Intended for bloodyAD functional-test labs only. Do not run on
    production infrastructure.
#>
[CmdletBinding()]
param(
    [string]$DomainName     = "bloody.corp",
    [string]$NetbiosName    = "BLOODY",
    [string]$ComputerName   = "MAIN",
    [string]$AdminPassword  = "Password123!"
)

$ErrorActionPreference = "Stop"

# Lab only: disable Windows Firewall so remote orchestration keeps working
# after each reboot. Do NOT copy this pattern into production.
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Host "=== bloodyAD lab bootstrap - stage 1 ===" -ForegroundColor Cyan
Write-Host "Target domain   : $DomainName" -ForegroundColor Cyan
Write-Host "NetBIOS name    : $NetbiosName" -ForegroundColor Cyan
Write-Host "Computer name   : $ComputerName" -ForegroundColor Cyan
Write-Host ""

# --- Rename the host if needed ---
if ($env:COMPUTERNAME -ne $ComputerName) {
    Write-Host "[+] Renaming computer to $ComputerName (reboot required)..." -ForegroundColor Yellow
    Rename-Computer -NewName $ComputerName -Force
    Write-Host "[!] Rebooting now. Re-run this script after reboot to continue." -ForegroundColor Red
    Start-Sleep -Seconds 3
    Restart-Computer -Force
    exit 0
}

# --- Install AD DS role ---
Write-Host "[+] Installing AD Domain Services role..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

# --- Promote to forest root DC ---
Write-Host "[+] Promoting to forest root DC for $DomainName ..." -ForegroundColor Yellow
Write-Host "    (this takes a few minutes and ends with a reboot)" -ForegroundColor Yellow

Import-Module ADDSDeployment
$securePw = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

$forestArgs = @{
    DomainName                    = $DomainName
    DomainNetbiosName             = $NetbiosName
    SafeModeAdministratorPassword = $securePw
    InstallDns                    = $true
    DomainMode                    = "WinThreshold"
    ForestMode                    = "WinThreshold"
    NoRebootOnCompletion          = $false
    Force                         = $true
}
Install-ADDSForest @forestArgs

# Reboot happens automatically. After reboot, log in as BLOODY\Administrator
# and run setup-dc-stage2.ps1.
