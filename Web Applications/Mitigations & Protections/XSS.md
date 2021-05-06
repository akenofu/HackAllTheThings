# Mitigations
## X-XSS-Protection
The HTTP **`X-XSS-Protection`** response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting ([XSS](https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting)) attacks. Although these protections are largely unnecessary in modern browsers when sites implement a strong [`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) that disables the use of inline JavaScript (`'unsafe-inline'`), they can still provide protections for users of older web browsers that don't yet support [CSP](https://developer.mozilla.org/en-US/docs/Glossary/CSP).

-   Chrome has [removed their XSS Auditor](https://www.chromestatus.com/feature/5021976655560704)
-   Firefox has not, and [will not implement `X-XSS-Protection`](https://bugzilla.mozilla.org/show_bug.cgi?id=528661)
-   Edge has [retired their XSS filter](https://blogs.windows.com/windowsexperience/2018/07/25/announcing-windows-10-insider-preview-build-17723-and-build-18204/)

`0`: Disables XSS filtering.
`1`: Enables XSS filtering (usually default in browsers). If a cross-site scripting attack is detected, the browser will sanitize the page (remove the unsafe parts).
`1; mode=block`: Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected.
`1; report=<reporting-URI> (Chromium only)`: Enables XSS filtering. If a cross-site scripting attack is detected, the browser will sanitize the page and report the violation. This uses the functionality of the CSP [`report-uri`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri) directive to send a report.

Reference: [X-XSS-Protection - HTTP | MDN (mozilla.org)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

***

## Content Security Policy