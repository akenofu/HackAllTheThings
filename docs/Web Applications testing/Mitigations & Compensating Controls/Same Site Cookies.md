# Same Site Cookies
- The **`SameSite`** attribute of the [`Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) HTTP response header allows you to declare if your cookie should be restricted to a [first-party](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#third-party_cookies) or same-site context.
- A cookie is associated with a domain. If this domain is the same as the domain of the page you are on, the cookie is called a _first-party cookie_. If the domain is different, it is a _third-party cookie_.
-  the server hosting a web page sets first-party cookies, the page may contain images or other components stored on servers in other domains (for example, ad banners), which may set third-party cookies
-  These are mainly used for advertising and tracking across the web.
![](/Screenshots/site-vs-origin.png)
### Same Site Cookie Values
`Set-Cookie: flavor=choco; SameSite=None;`   
#### Lax
Cookies are not sent on normal cross-site subrequests (for example to load images or frames into a third party site), but are sent when a user is _navigating to_ the origin site (i.e. when following a link).
`Set-Cookie: flavor=choco; SameSite=Lax;` 
#### Strict
`Set-Cookie: flavor=choco; SameSite=Strict; Secure` Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites.

#### Default If not specified
The `SameSite=Lax` is the default cookie value if `SameSite` has not been explicitly specified in recent browser versions

![Pasted image 20210430045738.png](/Screenshots/Pasted%20image%2020210430045738.png)

[Bypassing SameSite cookie restrictions | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)