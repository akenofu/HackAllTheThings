#### Setup TCP Dump on Device
`adb push c:\AndroidTools\tcpdump /data/local/tmp/tcpdump`
`adb shell`
`su`
`mount -o rw,remount /system;` or `mount -o rw,remount /`
`cp /data/local/tmp/tcpdump /system/xbin/`
`cd /system/xbin`
`chmod 755 tcpdump`


####  Setup Burp
Configure Burp on computer
[Configuring an Android Device to Work With Burp - PortSwigger](https://portswigger.net/support/configuring-an-android-device-to-work-with-burp)

