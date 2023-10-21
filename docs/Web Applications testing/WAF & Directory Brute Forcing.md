## WAF & Bruteforcing

The AWS WAF account takeover prevention (ATP) managed rule group inspects malicious requests that attempt to take over your account. For example, brute force login attacks that use trial and error to guess credentials and gain unauthorized access to your account.

The ATP rule group is an AWS [managed rule group](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html) that contains predefined rules that provide visibility and control over requests performing anomalous login attempts.

Use the following subset of rules in the ATP rule group to help block brute force attacks:

- VolumetricIpHigh 
	Inspects for high volumes of requests sent from individual IP addresses.

- AttributePasswordTraversal  
	Inspects for attempts that use password traversal.

- AttributeLongSession  
	Inspects for attempts that use long lasting sessions.

- AttributeUsernameTraversal  
	Inspects for attempts that use username traversal.

- VolumetricSession
Inspects for high volumes of requests sent from individual sessions.

- MissingCredential  
	Inspects for missing credentials.


## WAF Bypass

A combination of the following could potenially help bypass a WAF when directory bruteforcing or login bruteforcing.

- Rotate your IP
- Use a Legitimate User Agent instead of feroxbuster, gobuster, nesus, etc...
- Rotate your user agent
- Add a delay between requests
- Randomize the delay between requests
- Limit the number of requests sent concurrently

References:
- [Prevent brute force attacks with AWS WAF (amazon.com)](https://aws.amazon.com/premiumsupport/knowledge-center/waf-prevent-brute-force-attacks/)

## Wordlists
- [trickest/wordlists: Real-world infosec wordlists, updated regularly (github.com)](https://github.com/trickest/wordlists)
- [trickest/mkpath: Make URL path combinations using a wordlist (github.com)](https://github.com/trickest/mkpath)
- [trickest/mksub: Generate tens of thousands of subdomain combinations in a matter of seconds (github.com)](https://github.com/trickest/mksub)