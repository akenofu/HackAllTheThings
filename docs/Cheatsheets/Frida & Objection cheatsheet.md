### Frida Over ssh
Setup frida over ssh
`ssh -L 27042:127.0.0.1:27042 root@192.168.1.17 -i C:\temp\op6`
Use -R flag on commands
`frida-ps -R`

### Frida with mobile plugged via USB
- List all currently installed apps 
	`frida-ps -Uai`
- Get objection shell
	`objection -g com.spotify.music explore`
- Objection application enviroment (inside objection shell)
	`env`
- List internal data directory
	`ls`
- Objection disable non-custom SSL pinning (inside objection shell)
	`android sslpinning disable`
- Patch apk for unrooted devices using objection
	```bash
	objection patchapk --source UnCrackable-Level1.apk
	```
	
### Trace Native Calls
- Trace a specific function
	```bash
	frida-trace -U -i "open" com.android.chrome
	```
- Trace all android JNI functions
	```bash
	frida-trace -U -i "Java_*" com.android.chrome
	```
- Trace function by address
	```bash
	frida-trace -p 1372 -a "libjpeg.so!0x4793c"
	```
- Use JNI trace to identify usage of Android's JNI API by native libraries
	```bash
	jnitrace -l libnative-lib.so sg.vantagepoint.helloworldjni
	```

### Frida Scripts
- run frida script on application package
	```bash
	frida -U -f owasp.mstg.uncrackable1 -l uncrackable1.js --no-pause
	```
- run script on pid
	```bash
	frida -U -l java_class_listing.js -p 10188
	```
- Enumerate modules
	```Java
	Process.enumerateModules()
	```
- Hook method and override it
	```javascript
	setImmediate(function() { //prevent timeout
	console.log("[*] Starting script");

	Java.perform(function() {
	  var mainActivity = Java.use("sg.vantagepoint.uncrackable1.MainActivity");
	  mainActivity.a.implementation = function(v) {
		 console.log("[*] MainActivity.a called");
	  };
	  console.log("[*] MainActivity.a modified");

	});
	});
	```
- Hook method and override it
	```javascript
	setImmediate(function() { //prevent timeout
	console.log("[*] Starting script");

	Java.perform(function() {
		var mainActivity = Java.use("sg.vantagepoint.uncrackable1.MainActivity");
		mainActivity.a.implementation = function(v) {
		   console.log("[*] MainActivity.a called");
		};
		console.log("[*] MainActivity.a modified");

		var aaClass = Java.use("sg.vantagepoint.a.a");
		aaClass.a.implementation = function(arg1, arg2) {
		var retval = this.a(arg1, arg2);
		var password = '';
		for(var i = 0; i < retval.length; i++) {
			password += String.fromCharCode(retval[i]);
		}

		console.log("[*] Decrypted: " + password);
			return retval;
		};
		console.log("[*] sg.vantagepoint.a.a.a modified");
	});
	});
	```

### Explore binaries
- Explore binary information with objection
	```bash
	objection --gadget sg.vantagepoint.helloworldjni explore
	```
- Explore modules in memory with objection ```memory list modules```