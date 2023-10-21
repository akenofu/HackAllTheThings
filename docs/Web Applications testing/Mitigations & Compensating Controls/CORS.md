# CORS
From: [Cross-Origin Resource Sharing (CORS) - HTTP | MDN (mozilla.org)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

**Cross-Origin Resource Sharing** ([CORS](https://developer.mozilla.org/en-US/docs/Glossary/CORS)) is an [HTTP](https://developer.mozilla.org/en-US/docs/Glossary/HTTP)-header based mechanism that allows a server to indicate any [origins](https://developer.mozilla.org/en-US/docs/Glossary/Origin) (domain, scheme, or port) other than its own from which a browser should permit loading resources. CORS also relies on a mechanism by which browsers make a "preflight" request to the server hosting the cross-origin resource, in order to check that the server will permit the actual request. In that preflight, the browser sends headers that indicate the HTTP method and headers that will be used in the actual request.

An example of a cross-origin request: the front-end JavaScript code served from `https://domain-a.com` uses [`XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) to make a request for `https://domain-b.com/data.json`.

For security reasons, browsers restrict cross-origin HTTP requests initiated from scripts. For example, `XMLHttpRequest` and the [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) follow the [same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy). This means that a web application using those APIs can only request resources from the same origin the application was loaded from unless the response from other origins includes the right CORS headers.

![](/Screenshots/Pasted%20image%2020230610212955.png)

### Simple requests

Some requests don't trigger a [CORS preflight](https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request). Those are called _simple requests_ from the obsolete [CORS spec](https://www.w3.org/TR/2014/REC-cors-20140116/#terminology), though the [Fetch spec](https://fetch.spec.whatwg.org/) (which now defines CORS) doesn't use that term.

The motivation is that the [`<form>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form) element from HTML 4.0 (which predates cross-site [`XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) and [`fetch`](https://developer.mozilla.org/en-US/docs/Web/API/fetch)) can submit simple requests to any origin, so anyone writing a server must already be protecting against [cross-site request forgery](https://developer.mozilla.org/en-US/docs/Glossary/CSRF) (CSRF). Under this assumption, the server doesn't have to opt-in (by responding to a preflight request) to receive any request that looks like a form submission, since the threat of CSRF is no worse than that of form submission. However, the server still must opt-in using [`Access-Control-Allow-Origin`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) to _share_ the response with the script.

A _simple request_ is one that **meets all the following conditions**:

- One of the allowed methods:
    - [`GET`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET)
    - [`HEAD`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD)
    - [`POST`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST)
- Apart from the headers automatically set by the user agent (for example, [`Connection`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection), [`User-Agent`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent), or [the other headers defined in the Fetch spec as a _forbidden header name_](https://fetch.spec.whatwg.org/#forbidden-header-name), the only headers which are allowed to be manually set are [those which the Fetch spec defines as a CORS-safelisted request-header](https://fetch.spec.whatwg.org/#cors-safelisted-request-header), which are:
    - [`Accept`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept)
    - [`Accept-Language`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language)
    - [`Content-Language`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Language)
    - [`Content-Type`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) (please note the additional requirements below)
    - [`Range`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range) (only with a [simple range header value](https://fetch.spec.whatwg.org/#simple-range-header-value); e.g., `bytes=256-` or `bytes=127-255`)

### Preflighted requests

Unlike [_simple requests_](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests), for "preflighted" requests the browser first sends an HTTP request using the [`OPTIONS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS) method to the resource on the other origin, in order to determine if the actual request is safe to send. Such cross-origin requests are preflighted since they may have implications for user data.

![](/Screenshots/Pasted%20image%2020230610213155.png)