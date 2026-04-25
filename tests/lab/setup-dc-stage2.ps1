<#
.SYNOPSIS
    Stage 2 of the bloodyAD test lab bootstrap: install AD Certificate
    Services with an Enterprise Root CA named bloody-MAIN-CA.

.DESCRIPTION
    Run this AFTER setup-dc-stage1.ps1 has promoted the box to a DC and
    rebooted. Log in as BLOODY\Administrator and execute this script.

    The resulting CA name matches what tests/test_functional.py expects
    (bloody-MAIN-CA, template "User"). After this script completes,
    the lab is ready to accept `python -m unittest tests.test_functional`.

.PARAMETER CaCommonName
    Common name of the enterprise root CA. Default: bloody-MAIN-CA
    (the string hardcoded in tests/test_functional.py line ~68).

.EXAMPLE
    PS> .\setup-dc-stage2.ps1

.NOTES
    Must be run as a member of Domain Admins / Enterprise Admins.
#>
[CmdletBinding()]
param(
    [string]$CaCommonName = "bloody-MAIN-CA"
)

$ErrorActionPreference = "Stop"

# Lab only: keep firewall off across reboots (see stage1 note).
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Host "=== bloodyAD lab bootstrap - stage 2 ===" -ForegroundColor Cyan
Write-Host "CA common name  : $CaCommonName" -ForegroundColor Cyan
Write-Host ""

# --- Sanity: we should be on a DC now ---
# Use -Server localhost because right after promotion the DNS-based
# locator can take a minute to settle, but the local LDAP is already
# answering.
try {
    $domain = (Get-ADDomain -Server localhost -ErrorAction Stop).DnsRoot
    Write-Host "[+] Running on DC for domain: $domain" -ForegroundColor Green
} catch {
    Write-Host "[!] Not running on a DC, or AD is not ready yet." -ForegroundColor Red
    Write-Host "    Did you run stage 1 first and reboot?" -ForegroundColor Red
    exit 1
}

# --- Install AD CS role + mgmt tools ---
Write-Host "[+] Installing AD Certificate Services role..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools | Out-Null

# --- Configure the Enterprise Root CA ---
Write-Host "[+] Configuring Enterprise Root CA: $CaCommonName ..." -ForegroundColor Yellow
$caArgs = @{
    CAType              = "EnterpriseRootCA"
    CACommonName        = $CaCommonName
    KeyLength           = 2048
    HashAlgorithmName   = "SHA256"
    ValidityPeriod      = "Years"
    ValidityPeriodUnits = 10
    Force               = $true
}
Install-AdcsCertificationAuthority @caArgs | Out-Null

# --- Configure Web Enrollment (certipy uses it in some flows) ---
Write-Host "[+] Configuring CA Web Enrollment..." -ForegroundColor Yellow
try {
    Install-AdcsWebEnrollment -Force | Out-Null
} catch {
    Write-Host "[!] Web enrollment setup failed (non-fatal): $_" -ForegroundColor Yellow
}

# --- Ensure the default "User" template is published (tests/test_functional.py uses it) ---
Write-Host "[+] Ensuring 'User' certificate template is published..." -ForegroundColor Yellow
try {
    certutil -SetCATemplates +User | Out-Null
    Write-Host "    User template published." -ForegroundColor Green
} catch {
    Write-Host "[!] Could not publish User template automatically. Publish it via certsrv.msc if tests fail." -ForegroundColor Yellow
}

# --- Restart the CA service so template changes take effect ---
Write-Host "[+] Restarting CertSvc..." -ForegroundColor Yellow
Restart-Service -Name CertSvc -Force

# --- Lab tweaks for bloodyAD test suite repeatability ---
# Tests change passwords immediately after setting them; default 1-day
# minimum password age would block this.
Write-Host "[+] Setting MinPasswordAge=0..." -ForegroundColor Yellow
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain -Server localhost).DistinguishedName -Server localhost -MinPasswordAge 00:00:00 -ErrorAction SilentlyContinue

Write-Host "[+] Resetting BLOODY\Administrator password to lab default..." -ForegroundColor Yellow
Set-ADAccountPassword -Identity Administrator -Server localhost -Reset -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# NOTE: do NOT enable AD Recycle Bin here. test_04 (set restore) appears
# to rely on traditional tombstone semantics, and Recycle Bin enable is
# irreversible per forest. If the lab gets polluted with leftover
# tombstones across runs, the cheapest fix is to redeploy this VM from
# the template clone rather than try to clean a single forest.

Write-Host ""
Write-Host "=== Lab ready ===" -ForegroundColor Green
Write-Host "Domain       : bloody.corp" -ForegroundColor Green
Write-Host "DC hostname  : main.bloody.corp" -ForegroundColor Green
Write-Host "Admin user   : BLOODY\Administrator" -ForegroundColor Green
Write-Host "CA name      : $CaCommonName" -ForegroundColor Green
Write-Host ""
Write-Host "Next: on your mac/linux client, update tests/secrets.json with this" -ForegroundColor Cyan
Write-Host "VM's IP + /etc/hosts entry, then run:"                                -ForegroundColor Cyan
Write-Host "    python -m unittest tests.test_functional -v"                      -ForegroundColor Cyan
