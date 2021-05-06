## Enumeration

### AD Enumeration With PowerView

```powershell
# Get all users in the current domain
Get-NetUser | select -ExpandProperty cn

# Get all computers in the current domain
Get-NetComputer

# Get all domains in current forest
Get-NetForestDomain

# Get domain/forest trusts
Get-NetDomainTrust
Get-NetForestTrust

# Get information for the DA group
Get-NetGroup -GroupName "Domain Admins"

# Find members of the DA group
Get-NetGroupMember -GroupName "Domain Admins" | select -ExpandProperty membername

# Find interesting shares in the domain, ignore default shares
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC

# Get OUs for current domain
Get-NetOU -FullData

# Get computers in an OU
# %{} is a looping statement
Get-NetOU -OUName StudentMachines | %{Get-NetComputer -ADSPath $_}

# Get GPOs applied to a specific OU
Get-NetOU *student* | select gplink
Get-NetGPO -Name "{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}"

# Get Restricted Groups set via GPOs, look for interesting group memberships forced via domain
Get-NetGPOGroup

# Get incoming ACL for a specific object
Get-ObjectACL -SamAccountName "Domain Admins" -ResolveGUIDs | Select IdentityReference,ActiveDirectoryRights

# Find interesting ACLs for the entire domain, show in a readable (left-to-right) format
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft

# Get interesting outgoing ACLs for a specific user or group
# ?{} is a filter statement
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReference -match "Domain Admins"} | select ObjectDN,ActiveDirectoryRights
```


***

### LAPS

We can use [LAPSToolkit.ps1](https://github.com/leoloobeek/LAPSToolkit/blob/master/LAPSToolkit.ps1) to identify which machines in the domain use LAPS, and which domain groups are allowed to read LAPS passwords. If we are in this group, we can get the current LAPS passwords using this tool as well.

```powershell
# Get computers running LAPS, along with their passwords if we're allowed to read those
Get-LAPSComputers

# Get groups allowed to read LAPS passwords
Find-LAPSDelegatedGroups
```

***

### BloodHound

Use `Invoke-BloodHound` from `SharpHound.ps1`, or use `SharpHound.exe`. Both can be ran reflectively, get them [here](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors).

```powershell
# Run all checks if you don't care about OpSec 🚩
Invoke-BloodHound -CollectionMethod All,GPOLocalGroup

# Running LoggedOn separately sometimes gives you more sessions, but enumerates by looping through hosts 🚩
Invoke-BloodHound -CollectionMethod LoggedOn
```

***

### Misc
[[Lateral Movment#Lateral Movement Enumeration With PowerView]]