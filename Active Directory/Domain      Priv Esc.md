## Constrained Delegation
- [Agent on a Computer Configured For Constrained Delegation](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [User Account Configured For Constrained Delegation + A Known Plaintext](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [User Account Configured For Constrained Delegation + A Known NTLM Hash](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [Computer Account Configured For Constrained Delegation + A Known NTLM Hash](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
***
## ACL Abuse
***
##  Resource Based Constrained Delegation
- Write privilege on computer object with msDSAllowedToActOnBehalfOfOTherIdentity ?
	- [Dfault policies for adding new computers present ?](https://decoder.cloud/2019/03/20/donkeys-guide-to-resource-based-constrained-delegation-from-standard-user-to-da/)
- LDAP Signing disabled ?
	- [Delegation Via Image Change](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
***
## Unconstrained Delegation
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