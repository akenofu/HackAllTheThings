#### General Purpose
Connect to device
`adb shell`

Copy file to device
`adb push test.txt /data/local/tmp/test.txt`

Copy file from device
`adb pull /sdcard/test.txt .`

Install apk from PC
`adb install C:\AndroidTools\PCAPdroid-v1.2.14-release.apk`


#### Extract package from rooted/non-rooted device
1. Get adb shell
2. List packages
`pm list packages`
or for third party packages and list their pathes
`adb shell pm list packages -3 -f`
3. Locate Package
`pm path com.spotify.music`
4. Copy package from device (doesn't run inside adb)
`adb pull "/data/app/com.spotify.music-J-tIOd-3de7W7Pj-HZ1nFQ==/base.apk" spotify.apk`