<#
.SYNOPSIS
    Applies a security-hardening baseline to the homelab-soc-iam lab.local domain.

.DESCRIPTION
    Blue-team / IAM hardening baseline:
      1. Strong password & account-lockout policy (domain-wide)
      2. Advanced audit policy (logon + object access) - feeds the SIEM in Phase 3
      3. Disable legacy/insecure protocols (LLMNR, NetBIOS-over-TCP)
      4. Create a DELIBERATELY WEAK Kerberoastable service account for Phase 4

    Run on DC01 in an ELEVATED PowerShell session (Run as Administrator).

.NOTES
    Domain      : lab.local
    Author      : Pradeep
    WARNING     : Item 4 intentionally introduces a vulnerability for later
                  attack/detect exercises. Do NOT use these patterns in production.
#>

Import-Module ActiveDirectory -ErrorAction Stop
$domain = (Get-ADDomain).DistinguishedName
Write-Host "Target domain: $domain" -ForegroundColor Cyan

# ===========================================================================
# BLOCK 5 - Password & account-lockout policy (Default Domain Policy)
# ---------------------------------------------------------------------------
# Sets a strong baseline via the domain's default password policy. In a real
# environment you would often use Fine-Grained Password Policies (PSOs) for
# different groups; here we set a solid domain-wide floor.
# ===========================================================================
Write-Host "`n[Block 5] Applying password & lockout policy..." -ForegroundColor Yellow

Set-ADDefaultDomainPasswordPolicy -Identity lab.local `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -ComplexityEnabled $true `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
    -ReversibleEncryptionEnabled $false

Write-Host "  MinLength=14, History=24, MaxAge=90d, Lockout=5 attempts/15min" -ForegroundColor Green
Write-Host "[Block 5] Password & lockout policy applied." -ForegroundColor Green

# ===========================================================================
# BLOCK 6 - Advanced audit policy
# ---------------------------------------------------------------------------
# Enables auditing of the events a SOC cares about. These Windows Security
# events are what Security Onion / your SIEM will ingest in Phase 3, and what
# lets you DETECT the Kerberoasting attack in Phase 4.
#   4768/4769 = Kerberos TGT/service-ticket requests (Kerberoasting signal)
#   4624/4625 = successful / failed logons
#   4720+     = account management changes
# auditpol is the supported way to set the "Advanced Audit Policy" subcategories.
# ===========================================================================
Write-Host "`n[Block 6] Configuring advanced audit policy..." -ForegroundColor Yellow

# Logon / account activity
auditpol /set /subcategory:"Logon"                  /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                 /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"        /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service"      /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"   /success:enable /failure:enable

# Account & group management (detect account creation/changes)
auditpol /set /subcategory:"User Account Management"  /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Object access & process tracking (useful detections downstream)
auditpol /set /subcategory:"Process Creation"        /success:enable /failure:enable

Write-Host "[Block 6] Audit policy configured (logon, Kerberos, account mgmt, process creation)." -ForegroundColor Green

# ===========================================================================
# BLOCK 7 - Disable legacy / insecure protocols
# ---------------------------------------------------------------------------
# LLMNR and NBT-NS are classic spoofing/credential-theft vectors (e.g.
# Responder attacks). Disabling them is a real, high-value hardening win.
# NOTE: LLMNR here is set on the DC via registry. To push it domain-wide you
# would link a GPO (see the GUI walkthrough) - this sets it locally on DC01.
# ===========================================================================
Write-Host "`n[Block 7] Disabling legacy protocols (LLMNR, NetBIOS)..." -ForegroundColor Yellow

# Disable LLMNR (Link-Local Multicast Name Resolution)
$dnsClientKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsClientKey)) { New-Item -Path $dnsClientKey -Force | Out-Null }
Set-ItemProperty -Path $dnsClientKey -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "  LLMNR disabled (EnableMulticast=0)" -ForegroundColor Green

# Disable NetBIOS over TCP/IP on all active adapters
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($a in $adapters) {
    # SetTcpipNetbios: 2 = disable NetBIOS over TCP/IP
    $a.SetTcpipNetbios(2) | Out-Null
}
Write-Host "  NetBIOS-over-TCP disabled on active adapters" -ForegroundColor Green
Write-Host "[Block 7] Legacy protocols disabled." -ForegroundColor Green

# ===========================================================================
# BLOCK 8 - Deliberately weak service account (FOR PHASE 4 ONLY)
# ---------------------------------------------------------------------------
# Creates a service account with a Service Principal Name (SPN) and a weak
# password. Having an SPN makes it Kerberoastable: any domain user can request
# a service ticket for it and crack the password offline. This is our
# INTENTIONAL vulnerability to attack and detect in Phase 4.
# The 4769 events generated when it is roasted are what the SIEM will flag.
# ===========================================================================
Write-Host "`n[Block 8] Creating deliberately weak (Kerberoastable) service account..." -ForegroundColor Yellow

$svcPath = "OU=ServiceAccounts,OU=Corp,$domain"
# Weak, crackable password ON PURPOSE - do not imitate in production.
$weakPassword = ConvertTo-SecureString "Summer2024" -AsPlainText -Force

New-ADUser `
    -Name                "svc-sql" `
    -SamAccountName      "svc-sql" `
    -UserPrincipalName   "svc-sql@lab.local" `
    -Path                $svcPath `
    -AccountPassword     $weakPassword `
    -PasswordNeverExpires $true `
    -Enabled             $true `
    -Description         "INTENTIONALLY WEAK - Phase 4 Kerberoasting target"

# Register an SPN -> makes the account Kerberoastable
setspn -S "MSSQLSvc/dc01.lab.local:1433" svc-sql | Out-Null

Write-Host "  svc-sql created with SPN MSSQLSvc/dc01.lab.local:1433 (Kerberoastable)" -ForegroundColor Green
Write-Host "[Block 8] Weak service account created." -ForegroundColor Green

# ===========================================================================
# VERIFY
# ===========================================================================
Write-Host "`n--- Password policy ---" -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy |
    Select-Object MinPasswordLength, PasswordHistoryCount, LockoutThreshold, ComplexityEnabled |
    Format-Table -AutoSize

Write-Host "`n--- Audit policy (logon category) ---" -ForegroundColor Cyan
auditpol /get /category:"Logon/Logoff"

Write-Host "`n--- Kerberoastable accounts (have an SPN) ---" -ForegroundColor Cyan
Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName |
    Select-Object Name, SamAccountName, ServicePrincipalName | Format-Table -AutoSize

Write-Host "`nHardening baseline applied." -ForegroundColor Green
