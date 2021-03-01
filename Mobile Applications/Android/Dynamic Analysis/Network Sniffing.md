#### Setup TCP Dump on Device
`adb push c:\AndroidTools\tcpdump /data/local/tmp/tcpdump`
`adb shell`
`su`
`mount -o rw,remount /system;` or `mount -o rw,remount /`
`cp /data/local/tmp/tcpdump /system/xbin/`
`cd /system/xbin`
`chmod 755 tcpdump`

#### Sniff Network Traffic
`tcpdump -i wlan0 -s0 -w  /sdcard/tcpdump.out`
`adb pull /sdcard/tcpdump.out .`


