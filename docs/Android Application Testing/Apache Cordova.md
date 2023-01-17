# Apache Cordova
## Local Storage
Cordova uses [google/leveldb](https://github.com/google/leveldb) to store Local Storage data. The levelDB could be found at `/data/data/<package_name>/app_webview/Default/Local\ Storage/leveldb/`Storage/leveldb/` 
## Remote Debugging Cordova Apps in Chrome
1. Hook `android.webkit.WebView` to enable debugging
2.  Create a frida script to patch WebViews to be debuggable. 
```js
Java.perform(function () {
    var Webview = Java.use("android.webkit.WebView")
    Webview.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("\n[+]Loading URL from", url);
        console.log("[+]Setting the value of setWebContentsDebuggingEnabled() to TRUE");
        this.setWebContentsDebuggingEnabled(true);
        this.loadUrl.overload("java.lang.String").call(this, url);
    }
});
```
3. Hook the application with `frida -U  -l hookWebViews.js <application_name>`
4. Inside chrome, navigate to `chrome://inspect`
[Debugging Cordova Applications (appknox.com)](https://www.appknox.com/security/debugging-cordova-applications)

## Checklist
- [ ] Check JavaScript includes and iframe for resources fetched from remote URLs[^1]
	- [ ] HSTS configured?
	- [ ] CSP Policy
- [ ] Is data encrypted at rest? [^2]
- [ ] Use InAppBrowser to render links outside of the website [^3]
- [ ] is Certificate pinning implemented?
- [ ] Check for SSL Issues [^3]
- [ ] Avoid Using `eval` 
- [ ] Check Plugins Installed

## Resources
[Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)

[^1]:  [Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[^2]: [cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)
[^3]: [Security Guide - Apache Cordova](https://cordova.apache.org/docs/en/11.x/guide/appdev/security/)