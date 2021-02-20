### Check AndroidManifest.xml for
```xml
	<network-security-config>
	   <base-config>
		  <trust-anchors>
			  <certificates src="system" />
			  <certificates src="user" />
		  </trust-anchors>
	   </base-config>
	</network-security-config>
```
or

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>
```