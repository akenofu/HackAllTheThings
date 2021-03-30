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

#### Logs

Save Logcat output to file
`adb logcat \> logcat.log`
Grab logs for specific package from file (App needs to be running)
`adb logcat | grep "$(adb shell ps | grep com.spotify.music | awk '{print $2}')"`
Grab logs for specific package from file with regex
`adb logcat -e <expr> | grep "$(adb shell ps | grep com.spotify.music | awk '{print $2}')"`

### Local Backups
- Generate Local Backup for package
	`adb backup -apk -nosystem com.mwr.example.sieve`
- Convert backup to tar
	`dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" > backup.tar`
	
	
#### Content Provider
- Query cotent provider (Inside adb shell)
	`content query --uri content://sg.vp.owasp_mobile.provider.College/students`
	
	#### Deeplinks
	- Send intent within devie
		```bash
		adb shell am start -W -a android.intent.action.VIEW -d "emailapp://composeEmail/to=your.boss@company.com&message=SEND%20MONEY%20TO%20HERE!&sendImmediately=true" com.emailapp.android
		```
		
