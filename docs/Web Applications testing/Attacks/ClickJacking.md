# ClickJacking
## Content Extraction
We could use the view-source: pseudo-protocol to load the HTML source code into an iframe.
```html
<iframe src="view-source:http:// victim.site/secretInfoHere/"></iframe>
```
>  This technique only works on Firefox, without the NoScript addon.


