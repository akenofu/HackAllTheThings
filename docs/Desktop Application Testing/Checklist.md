Based on [OWASP Desktop App Security Top 10](https://owasp.org/www-project-desktop-app-security-top-10/) and the following articles:
1. [Thick Client Application Security Testing](https://www.optiv.com/insights/source-zero/blog/thick-client-application-security-testing)
2. [Thick Client Application Security Assessment](https://www.einfochips.com/blog/thick-client-application-security-assessment/)

> To comply with the checklist format the full attack scenario, Exploitability Rational, Impact and Prevention sections from the original OWASP document have been omitted in this checklist.


# DA1 - Injections
- [ ] Where does the application store authentication and authorization information?
- [ ] is it possible to inject into that storage container (config XML files, embedded in binary, etc...)
- [ ] Common injection vulnerabilities e.g. SQL, LDAPflee, XPATH, command injection or XSS
- [ ] Does application render data? is an HTML injection or a template injection possible?
- [ ] Common injection vulnerabilities in the related infrastructure e.g. APIs, WebApps, etc...


# DA2 - Broken Authentication and Session Management
- [ ] Does the application use a custom application layer authentication or inherit Authentication of Windows/nix OS? 
- [ ] Does  the application has 2FA
- [ ] Does the application authenticate from external things like RFID Authentication cards / USB Keys etc... ?
- [ ] Does the application explicitly rely upon platform security e.g. Windows Authentication without explicitly asking for authentication ?
- [ ] does the application have proper role based access controls that interact with the server?
- [ ] Are these role based access controls implemented application side only?
- [ ] Are concurrent logins supported ?

# DA3 - Sensitive Data Exposure
- [ ] Is sensitive data encrypted at rest?
- [ ] Is it possible to dump the process memory?
- [ ] is it possible to dump user sensitive data from memory after user has logged out?
- [ ] Are API keys or developer related keys hardcoded in executable or config files?

# DA4 - Improper Cryptography Usage
- [ ] Does the application use Outdated Cryptographic Algorithms? 
- [ ] Does the application use weak keys?
- [ ] Does the application employ the correct form of Cryptographic Function? e.g. encryption instead of hashing for password storage
- [ ] Does the application have it's custom crypto implementation?

# DA5 - Improper Authorization
- [ ] Does the application have weak file/folder permission per user role?
- [ ] Does the application enable unauthorized registry or environment variables access?
- [ ] Does the application run as root? Does it need root privs?
- [ ] Does the application run with setuid/setguid permissions? (NIX only)
- [ ] Can a limited access user replace legitimate files with malicious executable containing shellcode to perform privilege escalation?
- [ ] Does the application store data in publicly readable/writable locations? 
> e.g. configuration files saved in public directories or configuration files with write access to other users (xx7) permissions on linux operating system or read-write-execute for everyone/non-admin in Windows. Similarly, executable files with write permission for low privileged users allows replacing legitimate files with malicious executable containing shellcode to perform privilege escalation.
- [ ] Can an unprivileged user read/modify registries used by the application?
- [ ] Does the application save security settings within the registry?
 > if these registry keys can be tampered by a limited user it may impose threat
- [ ] Does the application prevent configuration alterations by using registry/group policies?
- [ ] Is the application susceptible to DLL Hijacking? 


# DA6 - Security Misconfiguration
- [ ] Does the application use misconfigured named-pipes for interprocess communication
- [ ] Does the application use background service misconfigured due to unquoted path in conjunction with weak folder permissions?
- [ ] Does the application use third-party services such as message queues, database services, etc. with default credentials, insecure access control, etc... ?
- [ ] Does the Application have file upload features to support creation of entities without file-type/content checking?
- [ ] Does the application expose services to the external network which shouldn't be exposed by design .e.g local webservers ?

# DA7 - Insecure Communication
- [ ] Does the application use plaintext communication protocols e.g. FTP, TELNET, HTTP, MQTT, WS , SQL?
- [ ] Does the application employ weak TLS/DTLS cipher-suites/protocols?
- [ ] Does the application use self signed certificates?
- [ ] Can the packets be relayed?
- [ ] Does the application leak any sensitive info in the traffic?
- [ ] Does the application have Insecure update management (e.g. insecure protocols for updates, untrusted sources for updates, unsigned patches) ?
- [ ] Are there outbound access controls in place?

# DA8 - Poor Code Quality
- [ ]  Does the application handle errors properly?
- [ ] Is the application code obfuscated?
- [ ] Is the application binary signed?
- [ ] Are there binary protections on the application e.g. ASLR, DEP?
- [ ] Does the application has dead code or test data in release build?
- [ ] Does the application omplement detection of code tampering?
 > via code signing and verification, detecting hooking of debuggers thereby preventing runtime debugging, etc.
 

# DA9 - Using Components with Known Vulnerabilities
- [ ] Does the application have any unpatched dependency with known exploits?
- [ ] Does the dependency chain have a vulnerable component? 
> for instance in your product ‘A’ you may be using 3rd party product/component ‘B’, in turn product ‘B’ uses another 3rd party product/component ‘C’. If a vulnerability within product ‘C’ is disclosed, by default product ‘A’ is vulnerable as it inherits via using component ‘B’.


# DA10 - Insufficient Logging & Monitoring
> Becomes very critical for publicly accessible devices such as kiosks and hospital devices.
- [ ] Does the application store application logs?
- [ ] Does the application have audit log capabilities?
- [ ] Does the application log sensitive data?
- [ ] Does the application Store logs in public folders with world read/writable permissions?
- [ ] Can Non-admin users access and update the audit logs?
- [ ] Can attackers inject into log files? 

