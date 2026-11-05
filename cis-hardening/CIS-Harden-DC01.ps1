#Requires -RunAsAdministrator
<#
  CIS-Harden-DC01.ps1
  Applies a lab-safe subset of the CIS Microsoft Windows Server 2022 Benchmark (domain controller)
  to DC01 in the homelab-soc-iam lab. Every setting is tagged with its CIS ID.

  NOT applied on purpose (see cis-hardening.md): Kerberos AES-only, LDAP signing / channel binding,
  NTLM minimum session security, UAC changes, account renames, Public-profile firewall merge settings,
  disabling IPv6, VBS / Credential Guard, and member-server-only checks.

  Before running : take a VirtualBox snapshot of DC01.
  After running  : restart DC01 (needed for LSA protection), then let the Wazuh agent rescan.
  Output         : applied-settings.csv next to this script.
#>

$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Cis)
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        $results.Add([pscustomobject]@{ CIS = $Cis; Setting = "$Path\$Name"; Value = "$Value"; Status = 'OK' })
    } catch {
        $results.Add([pscustomobject]@{ CIS = $Cis; Setting = "$Path\$Name"; Value = "$Value"; Status = "FAILED: $($_.Exception.Message)" })
    }
}

function Set-Audit {
    param([string]$Subcategory, [switch]$Success, [switch]$Failure, [string]$Cis)
    $auditArgs = @("/set", "/subcategory:$Subcategory")
    if ($Success) { $auditArgs += "/success:enable" }
    if ($Failure) { $auditArgs += "/failure:enable" }
    $out = & auditpol.exe @auditArgs 2>&1
    $status = if ($LASTEXITCODE -eq 0) { 'OK' } else { "FAILED: $out" }
    $results.Add([pscustomobject]@{ CIS = $Cis; Setting = "auditpol: $Subcategory"; Value = (($auditArgs | Select-Object -Skip 2) -join ' '); Status = $status })
}

$sys   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$prn   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$tcp   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$tcp6  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
$netbt = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
$rdp   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$def   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$evt   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog'

Write-Host "1/10 Password policy support" -ForegroundColor Cyan
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits' 1 -Cis '1.1.6'

Write-Host "2/10 Audit policy" -ForegroundColor Cyan
Set-Reg $lsa 'SCENoApplyLegacyAuditPolicy' 1 -Cis '2.3.2.1'
Set-Audit 'Credential Validation'            -Success -Failure -Cis '17.1.1'
Set-Audit 'Application Group Management'     -Success -Failure -Cis '17.2.1'
Set-Audit 'Distribution Group Management'    -Success          -Cis '17.2.3'
Set-Audit 'Other Account Management Events'  -Success          -Cis '17.2.4'
Set-Audit 'Plug and Play Events'             -Success          -Cis '17.3.1'
Set-Audit 'Directory Service Access'                  -Failure -Cis '17.4.1'
Set-Audit 'Directory Service Changes'        -Success          -Cis '17.4.2'
Set-Audit 'Group Membership'                 -Success          -Cis '17.5.2'
Set-Audit 'Other Logon/Logoff Events'        -Success -Failure -Cis '17.5.5'
Set-Audit 'Detailed File Share'                       -Failure -Cis '17.6.1'
Set-Audit 'File Share'                       -Success -Failure -Cis '17.6.2'
Set-Audit 'Other Object Access Events'       -Success -Failure -Cis '17.6.3'
Set-Audit 'Removable Storage'                -Success -Failure -Cis '17.6.4'
Set-Audit 'Authorization Policy Change'      -Success          -Cis '17.7.3'
Set-Audit 'MPSSVC Rule-Level Policy Change'  -Success -Failure -Cis '17.7.4'
Set-Audit 'Other Policy Change Events'                -Failure -Cis '17.7.5'
Set-Audit 'Sensitive Privilege Use'          -Success -Failure -Cis '17.8.1'
Set-Audit 'IPsec Driver'                     -Success -Failure -Cis '17.9.1'
Set-Audit 'Security System Extension'        -Success          -Cis '17.9.4'

Write-Host "3/10 Logging and visibility" -ForegroundColor Cyan
Set-Reg "$evt\Application" 'MaxSize' 32768  -Cis '18.10.26.1.2'
Set-Reg "$evt\Security"    'MaxSize' 196608 -Cis '18.10.26.2.2'
Set-Reg "$evt\Setup"       'MaxSize' 32768  -Cis '18.10.26.3.2'
Set-Reg "$evt\System"      'MaxSize' 32768  -Cis '18.10.26.4.2'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' 'WarningLevel' 90 -Cis '18.5.12'
Set-Reg "$sys\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1 -Cis '18.9.3.1'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 -Cis '18.10.87.1'
New-Item -Path 'C:\PSTranscripts' -ItemType Directory -Force | Out-Null
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1 -Cis '18.10.87.2'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' 'C:\PSTranscripts' -Type String -Cis '18.10.87.2'

Write-Host "4/10 Logon, credential and authentication hardening" -ForegroundColor Cyan
Set-Reg $sys 'NoConnectedUser' 3 -Cis '2.3.1.1'
Set-Reg $sys 'DontDisplayLastUserName' 1 -Cis '2.3.7.2'
Set-Reg $sys 'InactivityTimeoutSecs' 900 -Cis '2.3.7.3'
Set-Reg $sys 'legalnoticetext' 'This system is part of a private security lab. Authorised use only. Activity is logged and monitored.' -Type String -Cis '2.3.7.4'
Set-Reg $sys 'legalnoticecaption' 'Authorised use only' -Type String -Cis '2.3.7.5'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption' '1' -Type String -Cis '2.3.7.9'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 -Cis '2.3.8.1'
Set-Reg $lsa 'DisableDomainCreds' 1 -Cis '2.3.10.4'
Set-Reg $lsa 'UseMachineId' 1 -Cis '2.3.11.1'
Set-Reg $lsa 'LmCompatibilityLevel' 5 -Cis '2.3.11.7'
Set-Reg $lsa 'RunAsPPL' 1 -Cis '18.9.25.2'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCustomSSPsAPs' 0 -Cis '18.9.25.1'
Set-Reg "$sys\CredSSP\Parameters" 'AllowEncryptionOracle' 0 -Cis '18.9.4.1'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' 1 -Cis '18.9.4.2'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest' 0 -Cis '18.10.89.1.3'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'DisableRunAs' 1 -Cis '18.10.89.2.4'

Write-Host "5/10 Print Spooler (PrintNightmare-class attacks)" -ForegroundColor Cyan
try {
    Stop-Service -Name Spooler -Force -ErrorAction Stop
    Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop
    $results.Add([pscustomobject]@{ CIS = '5.1'; Setting = 'Service: Spooler'; Value = 'Disabled'; Status = 'OK' })
} catch {
    $results.Add([pscustomobject]@{ CIS = '5.1'; Setting = 'Service: Spooler'; Value = 'Disabled'; Status = "FAILED: $($_.Exception.Message)" })
}
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'RpcAuthnLevelPrivacyEnabled' 1 -Cis '18.4.2'
Set-Reg $prn 'RegisterSpoolerRemoteRpcEndPoint' 2 -Cis '18.7.1'
Set-Reg $prn 'RedirectionguardPolicy' 1 -Cis '18.7.2'
Set-Reg $prn 'ForceKerberosForRpc' 1 -Cis '18.7.6'
Set-Reg $prn 'RpcTcpPort' 0 -Cis '18.7.7'
Set-Reg "$prn\PointAndPrint" 'RestrictDriverInstallationToAdministrators' 1 -Cis '18.7.8'
Set-Reg $prn 'CopyFilesPolicy' 1 -Cis '18.7.9'
Set-Reg $prn 'DisableWebPnPDownload' 1 -Cis '18.9.20.1.1'
Set-Reg $prn 'DisableHTTPPrinting' 1 -Cis '18.9.20.1.6'

Write-Host "6/10 Legacy protocols and network stack" -ForegroundColor Cyan
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 -Cis '18.4.4'
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10') {
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 -Cis '18.4.3'
} else {
    $results.Add([pscustomobject]@{ CIS = '18.4.3'; Setting = 'mrxsmb10'; Value = '-'; Status = 'SKIPPED: SMBv1 client driver not installed' })
}
Set-Reg $netbt 'NodeType' 2 -Cis '18.4.6'
Set-Reg $netbt 'NoNameReleaseOnDemand' 1 -Cis '18.5.6'
Set-Reg $tcp6 'DisableIPSourceRouting' 2 -Cis '18.5.2'
Set-Reg $tcp  'DisableIPSourceRouting' 2 -Cis '18.5.3'
Set-Reg $tcp  'EnableICMPRedirect' 0 -Cis '18.5.4'
Set-Reg $tcp  'KeepAliveTime' 300000 -Cis '18.5.5'
Set-Reg $tcp  'PerformRouterDiscovery' 0 -Cis '18.5.7'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1 -Cis '18.5.8'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScreenSaverGracePeriod' '5' -Type String -Cis '18.5.9'
Set-Reg $tcp6 'TcpMaxDataRetransmissions' 3 -Cis '18.5.10'
Set-Reg $tcp  'TcpMaxDataRetransmissions' 3 -Cis '18.5.11'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0 -Cis '18.6.8.1'
$hp = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
foreach ($share in '\\*\NETLOGON', '\\*\SYSVOL') {
    & reg.exe add $hp /v $share /t REG_SZ /d 'RequireMutualAuthentication=1, RequireIntegrity=1' /f | Out-Null
    $results.Add([pscustomobject]@{ CIS = '18.6.14.1'; Setting = "$hp\$share"; Value = 'RequireMutualAuthentication=1, RequireIntegrity=1'; Status = $(if ($LASTEXITCODE -eq 0) { 'OK' } else { 'FAILED' }) })
}

Write-Host "7/10 AutoPlay and AutoRun" -ForegroundColor Cyan
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 -Cis '18.10.7.1'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1 -Cis '18.10.7.2'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 -Cis '18.10.7.3'

Write-Host "8/10 Remote Desktop" -ForegroundColor Cyan
Set-Reg $rdp 'DisablePasswordSaving' 1 -Cis '18.10.57.2.2'
Set-Reg $rdp 'fDisableCdm' 1 -Cis '18.10.57.3.3.3'
Set-Reg $rdp 'fPromptForPassword' 1 -Cis '18.10.57.3.9.1'
Set-Reg $rdp 'fEncryptRPCTraffic' 1 -Cis '18.10.57.3.9.2'
Set-Reg $rdp 'UserAuthentication' 1 -Cis '18.10.57.3.9.4'
Set-Reg $rdp 'MinEncryptionLevel' 3 -Cis '18.10.57.3.9.5'
Set-Reg $rdp 'MaxIdleTime' 900000 -Cis '18.10.57.3.10.1'
Set-Reg $rdp 'MaxDisconnectionTime' 60000 -Cis '18.10.57.3.10.2'

Write-Host "9/10 Microsoft Defender" -ForegroundColor Cyan
Set-Reg "$def\MpEngine" 'EnableFileHashComputation' 1 -Cis '18.10.43.7.1'
Set-Reg "$def\Scan" 'DisableRemovableDriveScanning' 0 -Cis '18.10.43.13.1'
Set-Reg "$def\Scan" 'DisableEmailScanning' 0 -Cis '18.10.43.13.2'
Set-Reg $def 'PUAProtection' 1 -Cis '18.10.43.16'

Write-Host "10/10 Windows Firewall (Domain, Private, Public)" -ForegroundColor Cyan
try { Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction Stop } catch { Write-Warning "Could not enable File and Printer Sharing rules: $($_.Exception.Message)" }
$fw = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$profiles = @(
    @{ Key = 'DomainProfile';  Log = 'domainfw.log';  Cis = '9.1' },
    @{ Key = 'PrivateProfile'; Log = 'privatefw.log'; Cis = '9.2' },
    @{ Key = 'PublicProfile';  Log = 'publicfw.log';  Cis = '9.3' }
)
foreach ($p in $profiles) {
    $k = "$fw\$($p.Key)"
    Set-Reg $k 'EnableFirewall' 1 -Cis "$($p.Cis).x state"
    Set-Reg $k 'DefaultInboundAction' 1 -Cis "$($p.Cis).x inbound"
    Set-Reg $k 'DefaultOutboundAction' 0 -Cis "$($p.Cis).x outbound"
    Set-Reg $k 'DisableNotifications' 1 -Cis "$($p.Cis).x notifications"
    Set-Reg "$k\Logging" 'LogFilePath' "%SystemRoot%\System32\logfiles\firewall\$($p.Log)" -Type ExpandString -Cis "$($p.Cis).x log name"
    Set-Reg "$k\Logging" 'LogFileSize' 16384 -Cis "$($p.Cis).x log size"
    Set-Reg "$k\Logging" 'LogDroppedPackets' 1 -Cis "$($p.Cis).x log dropped"
    Set-Reg "$k\Logging" 'LogSuccessfulConnections' 1 -Cis "$($p.Cis).x log allowed"
}

$csv = Join-Path $PSScriptRoot 'applied-settings.csv'
$results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
$ok = ($results | Where-Object Status -eq 'OK').Count
$bad = $results | Where-Object { $_.Status -ne 'OK' }
Write-Host ""
Write-Host "Applied $ok settings. Log written to $csv" -ForegroundColor Green
if ($bad) { Write-Host "Not applied:" -ForegroundColor Yellow; $bad | Format-Table CIS, Setting, Status -AutoSize }
Write-Host "Next: set the account policies in the Default Domain Policy GPO, run gpupdate /force, then restart DC01." -ForegroundColor Yellow
