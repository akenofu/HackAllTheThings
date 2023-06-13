# SSL Strip attack
## Explanation
Instead of the victim connecting directly to a website; the victim would connect to the attacker, and the attacker would initiate the connection back to the website. This attack is known as an on-path attack.

The magic of SSLStrip was that whenever it would spot a link to a HTTPS webpage on an unencrypted HTTP connection, it would replace the HTTPS with a HTTP and sit in the middle to intercept the connection. The interceptor would make the encrypted connection to back to the web server in HTTPS, and serve the traffic back to the site visitor unencrypted (logging any interesting passwords or credit card information in the process).

Reference:
[Performing & Preventing SSL Stripping: A Plain-English Primer](https://blog.cloudflare.com/performing-preventing-ssl-stripping-a-plain-english-primer/)

## Mitigations
### [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
The first time your site is accessed using HTTPS and it returns the `Strict-Transport-Security` header, the browser records this information, so that future attempts to load the site using HTTP will automatically use HTTPS instead.

When the expiration time specified by the Strict-Transport-Security header elapses, the next attempt to load the site via HTTP will proceed as normal instead of automatically using HTTPS.

Whenever the Strict-Transport-Security header is delivered to the browser, it will update the expiration time for that site, so sites can refresh this information and prevent the timeout from expiring. Should it be necessary to disable Strict Transport Security, setting the max-age to 0 (over a https connection) will immediately expire the `Strict-Transport-Security` header, allowing access via http.

Reference: 
[MSDN Web Docs - Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

