$domain = (Get-ADDomain).DistinguishedName
$svcPath = "OU=ServiceAccounts,OU=Corp,$domain"

# Meets the 14-char complexity policy, but still weak/crackable on purpose
$weakPassword = ConvertTo-SecureString "Summer2024!Lab" -AsPlainText -Force

New-ADUser `
    -Name                "svc-sql" `
    -SamAccountName      "svc-sql" `
    -UserPrincipalName   "svc-sql@lab.local" `
    -Path                $svcPath `
    -AccountPassword     $weakPassword `
    -PasswordNeverExpires $true `
    -Enabled             $true `
    -Description         "INTENTIONALLY WEAK - Phase 4 Kerberoasting target"

# Register a Service Principal Name -> this is what makes it Kerberoastable
setspn -S "MSSQLSvc/dc01.lab.local:1433" svc-sql