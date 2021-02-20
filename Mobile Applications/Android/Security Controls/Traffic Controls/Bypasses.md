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
