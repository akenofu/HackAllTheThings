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
#### Identify method to hook