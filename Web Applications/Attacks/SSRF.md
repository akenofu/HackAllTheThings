# SSRF
## Impact
- Sensitive information disclosure
- Stealing authentication information (e.g., Windows NTLM hashes)
- File read/inclusion
- Remote Code Execution
- Portscan internal ports/local network machines

## Filter Bypasses
- Try using Ipv6 Address for localhost
- Try Hex/Octal Address Encoding 


### SSRF with blacklist-based input filters
Some applications block input containing hostnames like `127.0.0.1` and `localhost`, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using various techniques:

-   Using an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`.
-   Registering your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose.
-   Obfuscating blocked strings using URL encoding or case variation.


## SSRF with whitelist-based input filters
Some applications only allow input that matches, begins with, or contains, a whitelist of permitted values. In this situation, you can sometimes circumvent the filter by exploiting inconsistencies in URL parsing.

The URL specification contains a number of features that are liable to be overlooked when implementing ad hoc parsing and validation of URLs:

![Pasted image 20210601024542.png](/Screenshots/Pasted%20image%2020210601024542.png)

You can embed credentials in a URL before the hostname, using the @ character. For example: `https://expected-host@evil-host`.
- Use the # character to indicate a URL fragment. For example: `https://evil-host#expected-host`.
- Leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`.
- URL-encode characters to confuse the URL-parsing code. Prticularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
- Use combinations of these techniques together.

## Bypassing SSRF filters via open redirection
suppose the user-submitted URL is strictly validated to prevent malicious exploitation of the SSRF behavior. However, the application whose URLs are allowed contains an open redirection vulnerability. Provided the API used to make the back-end HTTP request supports redirections, you can construct a URL that satisfies the filter and results in a redirected request to the desired back-end target.

For example, suppose the application contains an open redirection vulnerability in which the following URL:

`/product/nextProduct?currentProductId=6&path=http://evil-user.net`

returns a redirection to:

`http://evil-user.net`

You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

> This  works because the application validates that the supplied stockAPI URL is on an allowed domain, then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attacker's choosing

## Blind SSRF with out-of-band detection
The most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques. This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system.

> Simply identifying a blind SSRF vulnerability that can trigger out-of-band HTTP requests doesn't in itself provide a route to exploitability.


## SSRF Via Referer Header
** Try Injecting in the `Referer` header **

Some applications employ server-side analytics software that tracks visitors. This software often logs the Referer header in requests, since this is of particular interest for tracking incoming links. Often the analytics software will actually visit any third-party URL that appears in the Referer header. This is typically done to analyze the contents of referring sites, including the anchor text that is used in the incoming links. **As a result, the Referer header often represents fruitful attack surface for SSRF vulnerabilities. **

> In Burp Suite Professional, install the "Collaborator Everywhere" extension from the BApp Store. Add the domain of the lab to Burp Suite's target scope, so that Collaborator Everywhere will target it.
