### Architecture
[Platform Overview - Mobile Security Testing Guide (gitbook.io)](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05a-platform-overview)

<br>

### How Android Apps Run
[How Android Apps are Built and Run · dogriffiths/HeadFirstAndroid Wiki (github.com)](https://github.com/dogriffiths/HeadFirstAndroid/wiki/How-Android-Apps-are-Built-and-Run)

<br>

### Reverse Enginnering
[maddiestone - YouTube](https://www.youtube.com/channel/UCTbTMfVyCfs9p8SPsi3xEZQ) 

<br>

### How Rooting Works under the hood
[rooting - How Magisk works? - Android Enthusiasts Stack Exchange](https://android.stackexchange.com/questions/213167/how-magisk-works)

<br>

### SSL Pinning
[Guide to Network Security Configuration in Android P | NowSecure](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)

#### Bypass SSL Pinning Manually
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