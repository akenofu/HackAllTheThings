# HTTP Host header
## HTTP Host header Injection
### Supply an arbitrary Host header
### Test for  for flawed validation
e.g. 
```
GET /example HTTP/1.1  
Host: vulnerable-website.com:bad-stuff-here
```

```
GET /example HTTP/1.1  
Host: notvulnerable-website.com
```

```
GET /example HTTP/1.1  
Host: hacked-subdomain.vulnerable-website.com
```
### Test For duplicate host headers
```
GET /example HTTP/1.1  
Host: vulnerable-website.com  
Host: bad-stuff-here
```
### Supply an absolute URL
Many servers are also configured to understand requests for absolute URLs. Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case. You can potentially exploit these discrepancies in much the same way as duplicate Host headers.
```
GET https://vulnerable-website.com/ HTTP/1.1  
Host: bad-stuff-here
```
> Note that you may also need to experiment with different protocols. Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL.

### Add line wrapping
Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value. Other servers will ignore the indented header altogether.
```
GET /example HTTP/1.1  
 Host: bad-stuff-here  
Host: vulnerable-website.com
```
Websites may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them like this.

### Inject host override headers
You can sometimes use `X-Forwarded-Host` to inject your malicious input while circumventing any validation on the Host header itself.

`GET /example HTTP/1.1  
Host: vulnerable-website.com  
X-Forwarded-Host: bad-stuff-here`

Although `X-Forwarded-Host` is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including:
-   `X-Host`
-   `X-Forwarded-Server`
-   `X-HTTP-Host-Override`
-   `X-Forwarded-Host`
-   `Forwarded`

> In Burp Suite, you can use the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist.


## Exploitation Scenarios
### Password reset poisoning
- Test forget password functionality
- Observe that you have received an email containing a link to reset your password. Notice that the URL contains the query parameter `temp-forgot-password-token`. 
- try to coerce webserver into sending the link to your server ,try:
	- change the Host header to an arbitrary value and still successfully trigger a password reset.
	- add the `X-Forwarded-Host` header or similar headers to req
- Confirm your server recieved the reset token for the user if he clicks the link
- Go to your email client and copy the genuine password reset URL from your first email. Visit this URL in your browser

### 