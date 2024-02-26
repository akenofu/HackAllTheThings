# WAF bypass 
## Leak Server IP Address
- Checkout the DNS trail of the hostname. This can be done using 
		[Security Trails - The World's Largest Repository of historical DNS data](https://securitytrails.com/dns-trails)
- DNS Lookups
	```bash
	dig example.com
	```
- Options method
	Sometimes the OPTIONS HTTP methods leaks the IP address of the server behind the WAF.
- HTTP Headers
	Try playing around with `X-Forwarded-For` and similar proxy headers to trigger a different response to the same page.
- Try to abuse the 8kB upload size on AWS WAF
- Scan the IP range using the hostname to identify the origin server.

## Blogs
- [New tool release: Discovering the origin host to bypass web application firewalls - Labs Detectify](https://labs.detectify.com/ethical-hacking/discovering-the-origin-host-to-bypass-waf/)
## Tools
- [hakluke/hakoriginfinder: Tool for discovering the origin host behind a reverse proxy. Useful for bypassing cloud WAFs! (github.com)](https://github.com/hakluke/hakoriginfinder)
### References:
- [How to find Origin IP | Medium](https://medium.com/@bobby.S/how-to-find-origin-ip-1f684f459942)

