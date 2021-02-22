#### Certificate Pinning
- Check AndroidManifest.xml for `trust-anchors`

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
	or `network_security_config` 

	```xml
	<?xml version="1.0" encoding="utf-8"?>
	<manifest ... >
		<application android:networkSecurityConfig="@xml/network_security_config"
						... >
			...
		</application>
	</manifest>
	```

	or `domain-config`

	```XML
	<?xml version="1.0" encoding="utf-8"?>
	<network-security-config>
		<base-config>
			<trust-anchors>
				<certificates src="system" />
				<certificates src="user" />
			</trust-anchors>
		</base-config>
		<domain-config>
			<domain includeSubdomains="false">owasp.org</domain>
			<trust-anchors>
				<certificates src="system" />
				<certificates src="user" />
			</trust-anchors>
			<pin-set expiration="2018/8/10">
				<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
				the Intermediate CA of the OWASP website server certificate -->
				<pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
				<!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
				the Root CA of the OWASP website server certificate -->
				<pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
			</pin-set>
		</domain-config>
	</network-security-config>
	```

	Note: If a value is not set in a `<domain-config\>`, the configurations in place will be based on the `<base-config\>`, and lastly if not defined in this entry, the default configuration will be used.

- Check logcat logs for
	`D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config`
	or in case of log pin validation failure `I/X509Util: Failed to validate the certificate chain, error: Pin verification failed`
	
	