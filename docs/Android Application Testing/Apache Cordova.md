# Apache Cordova
## Config
After unpacking the apk, the apache Cordova config file is located in `./res/xml/config.xml` .
## Local Storage
Cordova uses [google/leveldb](https://github.com/google/leveldb) for Local Storage of data. On Android, LevelDB is located at `/data/data/<package_name>/app_webview/Default/Local\ Storage/leveldb/Storage/leveldb/` 
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
3. Start the application with hooking in place
	`frida -U  -l hookWebViews.js -f <application_name>`
5. Inside chrome, navigate to `chrome://inspect`

From: [Debugging Cordova Applications (appknox.com)](https://www.appknox.com/security/debugging-cordova-applications)

## Checklist
- [ ] Check JavaScript includes and iframes for resources fetched remotely[^1]
	- [ ] HSTS configured?
	- [ ] CSP Policy?
- [ ] Are allows lists enabled? [^4]
	- [ ] Overly permissive origin allow list?
	- [ ] Network Request Allow List?
	- [ ] Navigation Allow List?
	- [ ] Intent Allow List?
- [ ] Is data encrypted at rest? [^2]
- [ ] Is InAppBrowser used to render links outside of the website [^3]
- [ ] is Certificate pinning implemented?
- [ ] Check for traditional SSL Issues [^3]
- [ ] is RootDetection implemented?
- [ ] Check for XSS issues. Cordova translates JavaScript calls to native Android Calls. XSS in a Cordova app could lead to a complete compromise of the application. 
- [ ] Check for  un-safe use of eval in custom code 
- [ ] Check Installed Plugins

## Resources
[Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)

[^1]:  [Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[^2]: [cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)
[^3]: [Security Guide - Apache Cordova](https://cordova.apache.org/docs/en/11.x/guide/appdev/security/)
[^4]: [Allow List Guide - Apache Cordova](https://cordova.apache.org/docs/en/11.x/guide/appdev/allowlist/index.html)