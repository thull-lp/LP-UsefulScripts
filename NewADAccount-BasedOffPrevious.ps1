
# Clear Host
Clear-Host

# Import ActiveDirectory Module
Import-Module ActiveDirectory

# Input Current AD Username
$OldUserName = Read-Host -Prompt "Enter Current AD Username"

# Exit out if unable to find AD User
Try {
    $OldADAccount = Get-ADUser -Identity $OldUserName -Properties *
}

Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "`rAD User not found. Exiting." -BackgroundColor Black -ForegroundColor Red
    Break
}

Write-Host "`nUser account found! Proceeding." -BackgroundColor Black -ForegroundColor Green

# Generate Passwords
Write-Host "`nGenerating Password... " -BackgroundColor Black -ForegroundColor Cyan -NoNewline
$Password = & "C:\Support\Scripts\PowerShell Password Generator\PassPharseGenerator.ps1"
$SecurePassword = & "C:\Support\Scripts\PowerShell Password Generator\PassPharseGenerator.ps1"; $SecurePassword += "#"
$SecurePasswordOldAccount = "$($Password)" | ConvertTo-SecureString -AsPlainText -Force
$SecurePasswordNewAccount = "$($SecurePassword)" | ConvertTo-SecureString -AsPlainText -Force
Write-Host "Generated! " -BackgroundColor Black -ForegroundColor Green

# Generate details for new AD Account
Write-Host "`nGenerating Splat... " -BackgroundColor Black -ForegroundColor Cyan -NoNewline
$NewADAccountDetails = @{
    AccountPassword = $SecurePasswordNewAccount
    ChangePasswordAtLogon = $False
    DisplayName = "$($OldADAccount.GivenName) $($OldADAccount.Surname)"
    EmailAddress = "$($OldADAccount.GivenName.ToLower()[0])$($OldADAccount.Surname.ToLower())@claremedical.com.au"
    Enabled = $True
    GivenName = $OldADAccount.GivenName
    Name = "$($OldADAccount.GivenName) $($OldADAccount.Surname)"
    Path = "OU=Users,OU=Clare Medical,DC=cmc,DC=local"
    SamAccountName = "$($OldADAccount.GivenName.ToLower()).$($OldADAccount.Surname.ToLower())"
    Surname = $OldADAccount.Surname
    Type = "User"
    UserPrincipalName = "$($OldADAccount.GivenName.ToLower()).$($OldADAccount.Surname.ToLower())@claremedical.com.au"
}
Write-Host "Generated!" -BackgroundColor Black -ForegroundColor Green
Write-Host @"
Splat details:
$($NewADAccountDetails | Out-String)
"@ -BackgroundColor Black -ForegroundColor Yellow

# Reset old AD Account password - to stop users from logging in with this account.
Write-Host "`nResetting password of Old AD Account - " -BackgroundColor Black -ForegroundColor Cyan -NoNewline
Try {
    Set-ADAccountPassword -Identity $OldUserName -Reset -NewPassword $SecurePasswordOldAccount
}

Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "`rCannot reset password, AD User not found." -BackgroundColor Black -ForegroundColor Red
    Break
}
Write-Host "Reset!" -BackgroundColor Black -ForegroundColor Green -NoNewline
Write-Host "    $($Password)" -BackgroundColor Black -ForegroundColor Yellow

# Disable old AD Account.
Write-Host "`nDisabling Old AD Account... " -BackgroundColor Black -ForegroundColor Cyan -NoNewline
Try {
    Set-ADUser -Identity $OldUserName -Enabled $False
}

Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "`rCannot disable, AD User not found." -BackgroundColor Black -ForegroundColor Red
    Break
}
Write-Host "Disabled!" -BackgroundColor Black -ForegroundColor Green

# Move old AD Account.
Move-ADObject -Identity $OldADAccount -TargetPath "OU=Disabled Users,OU=Users,OU=Clare Medical,DC=cmc,DC=local"

# Create new AD Account
Write-Host "`nCreating new AD Account... " -BackgroundColor Black -ForegroundColor Cyan -NoNewline
New-ADUser @NewADAccountDetails
Write-Host "Created!" -BackgroundColor Black -ForegroundColor Green -NoNewline
Write-Host "    $($SecurePassword)" -BackgroundColor Black -ForegroundColor Yellow

# Add new AD account to previous account AD groups
$OldADAccount.MemberOf | ForEach-Object {Add-ADGroupMember -Identity $_ -Members $NewADAccountDetails.SamAccountName}