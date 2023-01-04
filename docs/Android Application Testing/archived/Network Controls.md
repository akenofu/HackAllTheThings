# Network Controls
## Certificate Pinning
### Identification
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
	

### Bypass
#### Client Isolation in Wireless Networks  
Setup Device Wifi proxy to 127.0.0.1:8080
`adb reverse tcp:8080 tcp:8080`

<br>

#### Non-Proxy Aware Apps
Redirect all outgoing port 80 traffic to proxy
`iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP\>:8080`
Confirm rule has been set in IP Tables
`iptables -t nat -L`
Reset IP tables and flush rules
`iptables -t nat -F`

<br>

#### Proxy Detection
- Use IP tables instead of system proxy

***

# SSL Pinning
 ## Disable non-custom SSL pinning with [[Frida & Objection cheatsheet#]]
 ## Custom SSL Pinning
 ### Statically
#### Replace the hash or domain
 - Search for certificate hash
	`grep -ri "sha256\\|sha1" ./smali`
- Replace hash with the hash of your proxy's CA
or
- modifying the domain name to a non-existing domain (original domain isn't pinned now)
#### Replace the certificate
- Find the certificate file
	`find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)`.
- Replace these files with your proxy's certificates (make sure they are in the correct format)
#### Add certificate  trust store files
- Find truststore files
	`find ./ -type f \\( -iname \\\*.jks -o -iname \\\*.bks \\)`
- Add proxy's certificates to the trustore(make sure they are in the correct format)

### Dynamically
- Identify method to hook
- Hook each method with Frida and print the arguments. 
- Modify the arguments to circumvent the implemented pinning.


---


---
# Misc
### Add Certificate to System certificates
##### Manually
[Installing Burp's CA Certificate in an Android Device - PortSwigger](https://portswigger.net/support/installing-burp-suites-ca-certificate-in-an-android-device)  
Convert .drt to .pem  
`openssl pkcs12 -export -in test.crt -inkey test.key -out test-combined.p12`  
Transfer .pem cert  
`openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1`  
`mv cacert.pem 9a5ba575.0`  
`adb shell`  
`su -`  
`mount -o rw,remount /`  
`adb push 9a5ba575.0 /system/etc/security/cacerts`  
`chmod 644 /system/etc/security/cacerts/9a5ba575.0`

<br>

##### MagiskTrustUserCerts
[NVISOsecurity/MagiskTrustUserCerts: A Magisk module that automatically adds user certificates to the system root CA store (github.com)](https://github.com/NVISOsecurity/MagiskTrustUserCerts) 

** Extra Stuff I like Doing **
- Drop out of scope requests Burp
- Add the target to scope

<br>

##### Patch APK
- Patch
`objection patchapk -s .\spotify.apk`
or
`objection patchapk -s .\spotify.apk --architecture arm64`
- Install
`adb install C:\AndroidTools\tmp\patched_spotify.apk`

<br>
