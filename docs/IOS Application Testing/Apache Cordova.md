# Apache Cordova
## Local Storage

Cordova uses [google/leveldb](https://github.com/google/leveldb) to store Local Storage data. The levelDB could be found at `/data/data/<package_name>/app_webview/Default/Local\ Storage/leveldb/`

## Checklist
- [ ] Check JavaScript includes for resources fetched from remote URLs? [^1]
	- [ ] HSTS configured?
	- [ ] CSP Policy
- [ ] Is data encrypted at rest? [^2]


## Resources
[Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)

[^1]:  [Security problems of Apache Cordova - steal the entire contents of the phone's memory card with one XSS - research.securitum.com](https://research.securitum.com/security-problems-of-apache-cordova-steal-the-entire-contents-of-the-phone_s-memory-card-with-one-xss/)
[^2]: [cordova-docs/cordova-security-data.md at master · MicrosoftDocs/cordova-docs · GitHub](https://github.com/MicrosoftDocs/cordova-docs/blob/master/articles/cordova-security/cordova-security-data.md)