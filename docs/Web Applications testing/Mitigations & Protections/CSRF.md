## Mitigations
### Same Site Cookie
### Explanation
#### Third Party Cookies
> **Third-party cookies** are those created by domains other than the one the user is visiting at the time, and are mainly used for tracking and online-advertising purposes.

Famous, and big advertisers buy advertisement rights over thousands of popular sites, and place permanent cookies on the users local machine. These cookies are identified on other websites as well where the same advertiser has more ads, thus showing ads based on your browsing history, age, gender, etc.

The cookies placed are third-party cookies, since these are placed not by the domain you are visiting, but by another domain whose ads are being hosted by that particular website.

#### Same Site Cookie 
The **`SameSite`** attribute of the [`Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) HTTP response header allows you to declare if your cookie should be restricted to a [first-party](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#third-party_cookies) or same-site context.

### Values
`Set-Cookie: flavor=choco; SameSite=None;`   
#### Lax
Cookies are not sent on normal cross-site subrequests (for example to load images or frames into a third party site), but are sent when a user is _navigating to_ the origin site (i.e. when following a link).
`Set-Cookie: flavor=choco; SameSite=Lax;` 
#### Strict
`Set-Cookie: flavor=choco; SameSite=Strict; Secure` Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites.

#### Default If not specified
The `SameSite=Lax` is the default cookie value if `SameSite` has not been explicitly specified in recent browser versions

![Pasted image 20210430045738.png](/Screenshots/Pasted%20image%2020210430045738.png)