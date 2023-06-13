# MIME Sniffing
## Explantation
1.  A web browser requests a particular asset which responds with either no content type or a content type previously set at the origin server.
2.  The web browser "sniffs" the content to analyze what file format that particular asset is.
3.  Once the browser has completed its analysis, it compares what it found against what the web server provided in the `Content-Type` header (if anything). If there is a mismatch, the browser uses the MIME type that **it determined to be associated with the asset.**

## Mitigation
### [X-Content-Type-Options - HTTP | MDN (mozilla.org)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
The `X-Content-Type-Options` response HTTP header is a marker used by the server to indicate that the [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) advertised in the [`Content-Type`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) headers should not be changed and be followed. This is a way to opt out of [MIME type sniffing](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing), or, in other words, to say that the MIME types are deliberately configured.

```
X-Content-Type-Options: nosniff
```

`nosniff`

Blocks a request if the request destination is of type:

-   "`style`" and the MIME type is not `text/css`, or
-   "`script`" and the MIME type is not a [JavaScript MIME type](https://html.spec.whatwg.org/multipage/scripting.html#javascript-mime-type)

Enables Cross-Origin Read Blocking (CORB) protection for the MIME-types:

-   `text/html`
-   `text/plain`
-   `text/json`, `application/json` or any other type with a JSON extension: `*/*+json`
-   `text/xml`, `application/xml` or any other type with an XML extension: `*/*+xml` (excluding `image/svg+xml`)