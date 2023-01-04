# Web cache poisoning
# Basics
## Constructing a web cache poisoning attack
### Identify and evaluate unkeyed inputs
#### Manual
Identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response.

> tools such as Burp Comparer to compare the response with and without the injected input

#### Automated
`Param Miner` burp extension runs in the background, sending requests containing different inputs from a built-in list of headers. If a request containing one of its injected inputs has an effect on the response, Param Miner logs in the "Output" tab of the extension ("Extender" > "Extensions" > "Param Miner" > "Output") if you are using Burp Suite Community 

 **Caution**: When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request. 

### Elicit a harmful response from the back-end server
Once you have identified an unkeyed input, the next step is to evaluate exactly how the website processes it.  If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning. 

### Get the response cached
Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers.

***

# Exploitation Methodology
## Identify a suitable cache oracle
A cache oracle is simply a page or endpoint that provides feedback about the cache's behavior. This needs to be cacheable and must indicate in some way whether you received a cached response or a response directly from the server.

This feedback could take various forms, such as:
	- An HTTP header that explicitly tells you whether you got a cache hit
	- Observable changes to dynamic content
	- Distinct response times

If you can identify that a specific third-party cache is being used, you can also consult the corresponding documentation. This may contain information about how the default cache key is constructed. You might even stumble across some handy tips and tricks, such as features that allow you to see the cache key directly.

## Probe key handling
The next step is to investigate whether the cache performs any additional processing of your input when generating the cache key.

You should specifically look at any transformation that is taking place. Is anything being excluded from a keyed component when it is added to the cache key? Common examples are excluding specific query parameters, or even the entire query string, and removing the port from the Host header.

- Is your input being normalized in any way? 
- How is your input stored? 
- Do you notice any anomalies?

## Identify an exploitable gadget
The final step is to identify a suitable gadget that you can chain with this cache key flaw. 

These gadgets will often be classic client-side vulnerabilities, such as reflected XSS and open redirects.

***

# Exploitation Scenarios
## Unkeyed port
The Host header is often part of the cache key and, as such, initially seems an unlikely candidate for injecting any kind of payload. However, some caching systems will parse the header and exclude the port from the cache key. 

**Scenarios**
- Consider a case where a redirect URL was dynamically generated based on the Host header. This might enable you to construct a denial-of-service attack by simply adding an arbitrary port to the request. All users who browsed to the home page would be redirected to a dud port, effectively taking down the home page until the cache expired.

- This kind of attack can be escalated further if the website allows you to specify a non-numeric port. You could use this to inject an XSS payload.

## Unkeyed query string
use the `Pragma: x-get-cache-key` header to display the cache key in the response. This applies to some of the other labs as well.

> You can use the Param Miner extension to automatically add a cache buster header to your requests. 

 Websites often exclude certain UTM analytics parameters from the cache key. such as the `utm_content` query parameter.

## Cache parameter cloaking
If you can work out how the cache parses the URL to identify and remove the unwanted parameters, you might find some interesting quirks. 

Of particular interest are any parsing discrepancies between the cache and the application.

## Exploiting parameter parsing quirks
### Scenario 1 
Some poorly written parsing algorithms will treat any `?` as the start of a new parameter, regardless of whether it's the first one or not.  Let's assume that the algorithm for excluding parameters from the cache key behaves in this way, but the server's algorithm only accepts the first `?` as a delimiter. 

Consider the following request: 
`GET /?example=123?excluded_param=bad-stuff-here`

In this case, the cache would identify two parameters and exclude the second one from the cache key. However, the server doesn't accept the second `?` as a delimiter and instead only sees one parameter, example, whose value is the entire rest of the query string, 

### Scenario 2
The Ruby on Rails framework, for example, interprets both ampersands (&) and semicolons (;) as delimiters. When used in conjunction with a cache that does not allow this, you can potentially exploit another quirk to override the value of a keyed parameter in the application logic. 

 `GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here`

As the names suggest, keyed_param is included in the cache key, but excluded_param is not. Many caches will only interpret this as two parameters, delimited by the ampersand:
   1. keyed_param=abc 
   2. excluded_param=123;keyed_param=bad-stuff-here 

Once the parsing algorithm removes the excluded_param, the cache key will only contain keyed_param=abc. On the back-end, however, Ruby on Rails sees the semicolon and splits the query string into three separate parameters:
1. keyed_param=abc 
2. excluded_param=123 
3. keyed_param=bad-stuff-here 

But now there is a duplicate keyed_param. This is where the second quirk comes into play. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final occurrence. The end result is that the cache key contains an innocent, expected parameter value, allowing the cached response to be served as normal to other users. On the back-end, however, the same parameter has a completely different value, which is our injected payload. It is this second value that will be passed into the gadget and reflected in the poisoned response.

This exploit can be especially powerful if it gives you control over a function that will be executed. For example, if a website is using JSONP to make a cross-domain request, this will often contain a callback parameter to execute a given function on the returned data:

`GET /jsonp?callback=innocentFunction`

In this case, you could use these techniques to override the expected callback function and execute arbitrary JavaScript instead. 

## Exploiting fat GET support
he HTTP method may not be keyed. This might allow you to poison the cache with a POST request containing a malicious payload in the body. Your payload would then even be served in response to users' GET requests. Although this scenario is pretty rare, you can sometimes achieve a similar effect by simply adding a body to a GET request to create a "fat" GET request:

```
GET /?param=innocent HTTP/1.1
…
param=bad-stuff-here 
```
 This is only possible if a website accepts GET requests that have a body, but there are potential workarounds. You can sometimes encourage "fat GET" handling by overriding the HTTP method, for example:

```
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```

As long as the `X-HTTP-Method-Override` header is unkeyed, you could submit a pseudo-POST request while preserving a GET cache key derived from the request line. 

## Exploiting dynamic content in resource imports

Imported resource files are typically static but some reflect input from the query string. This is mostly considered harmless because browsers rarely execute these files when viewed directly, and an attacker has no control over the URLs used to load a page's subresources. However, by combining this with web cache poisoning, you can occasionally inject content into the resource file.

For example, consider a page that reflects the current query string in an import statement:

```
GET /style.css?excluded_param=123);@import… HTTP/1.1

HTTP/1.1 200 OK
…
@import url(/site/home/index.part1.8a6715a2.css?excluded_param=123);@import…
```

You could exploit this behavior to inject malicious CSS that exfiltrates sensitive information from any pages that import /style.css.

If the page importing the CSS file doesn't specify a doctype, you can maybe even exploit static CSS files. Given the right configuration, browsers will simply scour the document looking for CSS and then execute it. This means that you can occasionally poison static CSS files by triggering a server error that reflects the excluded query parameter:

```
GET /style.css?excluded_param=alert(1)%0A{}*{color:red;} HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html
…
```
This request was blocked due to…alert(1){}*{color:red;}

## Normalized cache keys
Any normalization applied to the cache key can also introduce exploitable behavior. In fact, it can occasionally enable some exploits that would otherwise be almost impossible.

For example, when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them. The response that the intended victim receives will merely contain a harmless URL-encoded string.

Some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key:

```
GET /example?param="><test>
GET /example?param=%22%3e%3ctest%3e
```

This behavior can allow you to exploit these otherwise "unexploitable" XSS vulnerabilities. If you send a malicious request using Burp Repeater, you can poison the cache with an unencoded XSS payload. When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload.

As a result, the cache will serve the poisoned response and the payload will be executed client-side. You just need to make sure that the cache is poisoned when the victim visits the URL.

## Cache key injection
Keyed components are often bundled together in a string to create the cache key. If the cache doesn't implement proper escaping of the delimiters between the components, you can potentially exploit this behavior to craft two different requests that have the same cache key.

The following example uses double-underscores to delimit different components in the cache key and does not escape them. You can exploit this by first poisoning the cache with a request containing your payload in the corresponding keyed header:

```
GET /path?param=123 HTTP/1.1
Origin: '-alert(1)-'__

HTTP/1.1 200 OK
X-Cache-Key: /path?param=123__Origin='-alert(1)-'__

<script>…'-alert(1)-'…</script>
```

If you then induce a victim user to visit the following URL, they would be served the poisoned response:

```
GET /path?param=123__Origin='-alert(1)-'__ HTTP/1.1

HTTP/1.1 200 OK
X-Cache-Key: /path?param=123__Origin='-alert(1)-'__
X-Cache: hit

<script>…'-alert(1)-'…</script>
```

## Poisoning internal caches
 Integrated caches are purpose-built for the specific application. Some of them instead of caching entire responses, some of these caches break the response down into reusable fragments and cache them each separately. For example, a snippet for importing a widely used resource might be stored as a standalone cache entry. Users might then receive a response comprising a mixture of content from the server, as well as several individual fragments from the cache.

As these cached fragments are intended to be reusable across multiple distinct responses, the concept of a cache key doesn't really apply. Every response that contains a given fragment will reuse the same cached fragment, even if the rest of the response is completely different. In a scenario like this, poisoning the cache can have wide-reaching effects, especially if you poison a fragment that is used on every page. As there is no cache key, you would have poisoned every page, for every user, with a single request.

## How to identify internal caches
For example, **if the response reflects a mixture of both input from the last request you sent and input from a previous request, this is a key indicator that the cache is storing fragments rather than entire responses**. The same applies if your input is reflected in responses on multiple distinct pages, in particular on pages in which you never tried to inject your input.

Other times, the cache's behavior may simply be so unusual that the most logical conclusion is that it must be a unique and specialized internal cache.

When a website implements multiple layers of caching, it can make it difficult to comprehend what is happening behind the scenes and understand how the website's caching system behaves.