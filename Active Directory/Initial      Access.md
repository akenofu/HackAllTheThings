## Phishing
### Proper OSINT
- LinkedIn
- Twitter
### Spear-phising
### Prepare Domain
- Check Domain Protection schemes
	- SPF
	- DMARC
	- tools
		- spoofcheck
- Setup convincing available tld
### Misc 
- Use company corporate mail if available
- Macros
- UNC mail injection

***

## Password Spraying
### Find Endpoint
- [ADFS / Azure AD](file:///C:/Users/karim/Downloads/Troopers%2019%20-%20I%20am%20AD%20FS%20and%20So%20Can%20You.pdf%20_%20Medium.html)
- Exchange Servers
- Kerberos
	- AS REP Preauth User/Password BruteForce
### Crack  Hashes
- ASREPRoast
- Kerberoasting

***

## Replay Attacks
- [ADFS](https://cqureacademy.com/blog/replaying-adfs-claims-with-fiddler)
- SMB
- RDP
- LDAP Relay
			
***

## Sniffing/MITM
- HTTP
- RDP MITM
- WAPD Injection
- SNMP v1,2 Community String Sniffing
- MITM IPV6
	- IPV6 Enabled ?
		- [WAPD abuse and NTLM Authentication Relay](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
		- [Abuse Resource Based delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
- LLMNR/NBNS