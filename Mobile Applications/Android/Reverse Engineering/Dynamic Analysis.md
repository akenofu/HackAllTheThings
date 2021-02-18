### Network Sniffing
[[Miscellaneous#Setup TCP Dump on Device]]
[[Miscellaneous#Setup Burp]]

#### Sniff Network Traffic
`tcpdump -i wlan0 -s0 -w  /sdcard/tcpdump.out`
`adb pull /sdcard/tcpdump.out .`


<br>

#### Bypass [[Fundmentals#SSL Pinning|SSL Pinning]]
##### Add Certificate to System certificates
- [[Fundmentals#SSL Pinning|Manually]]
- MagiskTrustUserCerts
[NVISOsecurity/MagiskTrustUserCerts: A Magisk module that automatically adds user certificates to the system root CA store (github.com)](https://github.com/NVISOsecurity/MagiskTrustUserCerts)

<br>

##### Patch APK
- Patch
`objection patchapk -s .\spotify.apk`
or
`objection patchapk -s .\spotify.apk --architecture arm64`
- Install
`adb install C:\AndroidTools\tmp\patched_spotify.apk`
