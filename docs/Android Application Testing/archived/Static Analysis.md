## Static Analysis
### Decompile APK to Java Source Code
- Unzip APK -> Convert DEX to JAR -> Convert Jar to java src files
- or automate the process using [apkx](https://github.com/b-mueller/apkx)
- Open decompiled code in Android Studio
- Delete the created Android Studio files by default
- Copy the decompiled Java src code to the Java folder

***

### Reverse Engineering Native Libraries
- Are native libraries used? Look for keywords `JavaSystem.loadLibrary`
- Look for .so file in the libs/ directory
- Search for the function offset in file
	```bash
	readelf  -W -s libnative-lib.so | grep Java
	```
- Load library into any disassembler

***

### Dump Strings
#### Dump Strings from DEX file
- unzip to extract DEX file using 
	```bash
	unzip UnCrackable-Level1.apk -d UnCrackable-Level1
	```
- Load DEX file into ghidra or use [dextra](http://newandroidbook.com/tools/dextra.htmlhttp://newandroidbook.com/tools/dextra.htmlhttp://newandroidbook.com/tools/dextra.html)
	```bash
	dextra -S classes.dex
	```
- Search for keywords such as passwords, keys, seceret, etc...

#### Dump Strings from native code
```bash
strings libnative-lib.so
```

#### Misc Ideas
- Check android documentation for releveant APIs that can be used for this application and search for those

***

### Use Static Analyzers
-   [Androbugs](https://github.com/AndroBugs/AndroBugs_Framework)
-   [JAADAS](https://github.com/flankerhqd/JAADAS)
-   [MobSF](/mobile-security-testing-guide/appendix/0x08-testing-tools#mobsf)    
-   [QARK](https://github.com/linkedin/qark/)


***
## Dynamic Analysis
### Information Gathering
- If using unrooted device, use objection to patch APK [[Frida & Objection cheatsheet]]
- List open files for specified process 
	```bash
	lsof -p 7894
	```
- List open connections for specified process
	```bash 
	cat /proc/7894/net/tcp
	```
- List connections using netstat
	```bash
	netstat -ntpl	
	# or
	ss -lntp
	```
- List loaded native libraries
	```bash
	cat /proc/7894/maps
	```
- Sandbox Inspection: The application data is stored in a sandboxed directory present at `/data/data/<app_package_name>`

### Debugging with jdb
- Make application show up as debuggable using magsik
	```bash
	adb shell
	su
	resetprop ro.debuggable 1
	stop
	start
	````
- Setup JDP [[adb Cheatsheet#Debug Debuggable Application with JDP]]
- Start jdb is suspended state 


### Debug APK with Android Studio
- Decompile project using [jadx-gui](https://github.com/skylot/jadx))
- Save src files
- Create new android studio project
- Replace src files there with decompiled src files
- On the device, choose the app as **debug app** on the "Developer options" (Uncrackable1 in this tutorial), and make sure you've switched on the "Wait For Debugger" feature.
- Set breakpoint at main activity `onCreate` to bypass root and debugging checks

***


## Dynamic Analysis
#### Automated
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)

#### Dynamic Analysis on Non-Rooted Devices
- Patch the apk -> include frida gadget library -> objection communicates with frida gadget api

```bash
# Download the Uncrackable APK
$ wget https://raw.githubusercontent.com/OWASP/owasp-mstg/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
# Patch the APK with the Frida Gadget
$ objection patchapk --source UnCrackable-Level1.apk
# Install the patched APK on the android phone
$ adb install UnCrackable-Level1.objection.apk
# After running the mobile phone, objection will detect the running frida-server through the APK
$ objection explore
```

***

### Native Code Tracing
- use `frida-trace` and `jnitrace` to trace native code calls [[Frida & Objection cheatsheet#Trace Native Calls]]  

***

## Tampering and Runtime Instrumentation
### Patching, Repackaging, and Re-Signing
- Unpack apk
	```bash
	apktool d target_apk.apk
	```
- Modify the manifest or code
- Repackage the APK
	```bash
	cd UnCrackable-Level1
	apktool b
	zipalign -v 4 dist/UnCrackable-Level1.apk ../UnCrackable-Repackaged.apk
	```
- Generate Code signing certificate
	```bash
	keytool -genkey -v -keystore ~/.android/debug.keystore -alias signkey -keyalg RSA -keysize 2048 -validity 20000
	```
- Re-sign the APK
	```bash
	jarsigner -verbose -keystore ~/.android/debug.keystore ./UnCrackable-Repackaged.apk signkey
	zipalign -v 4 ./UnCrackable-Level1.apk ./UnCrackable-Repackaged-Signed.apk	
	```
- Start the app "Developer options" contain the useful "Wait for Debugger" feature, which allows you to automatically suspend an app doing startup until a JDWP debugger connects

## Patching React Native applications
### Extract JS file
- Main Application code saved at `assets/index.android.bundle`
- Beautify the file using [JStillery (mindedsecurity.github.io)](https://mindedsecurity.github.io/jstillery/) . Note: use CLI version to avoid code disclosure to 3rd party
### Patch JS file
- Unpack the APK archive using `apktool` tool
- Copy the content of the file `assets/index.android.bundle` into a temporary file.
- Use `JStillery` to beautify and deobfuscate the content of the temporary file.
- Put the _patched code_ on a single line and copy it in the original `assets/index.android.bundle` file.
- Repack the APK archive using `apktool`

***

## Library Injection
### Patching the Application's Smali Code
- An Android application's decompiled smali code can be patched to introduce a call to `System.loadLibrary`
	```vim
	const-string v0, "inject"
	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
	```
- Insert the previous code early in the App life cycle such as `onCreate`
- add the library libinject.so in the respective architecture folder
- resign the application
### Patching Application's Native Library
- Use [LIEF (quarkslab.com)](https://lief.quarkslab.com/) to patch elf libraries
	```python
	libnative = lief.parse("libnative.so")
	libnative.add_library("libinject.so") # Injection!
	libnative.write("libnative.so")
	```
### Preloading Symbols
- Please note that if the library to be preloaded does not have SELinux context assigned, from Android 5.0 (API level 21) onwards, you need to disable SELinux to make `LD_PRELOAD` work, which may require root. 
	```bash
	setprop wrap.com.foo.bar LD_PRELOAD=/data/local/tmp/libpreload.so
	```
***
### Dynamic Instrumentation
- Frida List classes methods js
	```js
	// Get list of loaded Java classes and methods

	// Filename: java_class_listing.js

	Java.perform(function() {
	Java.enumerateLoadedClasses({
	onMatch: function(className) {
	console.log(className);
	describeJavaClass(className);
	},
	onComplete: function() {}
	});
	});

	// Get the methods and fields
	function describeJavaClass(className) {
	var jClass = Java.use(className);
	console.log(JSON.stringify({
	_name: className,
	_methods: Object.getOwnPropertyNames(jClass.__proto__).filter(function(m) {
	return !m.startsWith('$') // filter out Frida related special properties
	|| m == 'class' || m == 'constructor' // optional
	}),
	_fields: jClass.class.getFields().map(function(f) {
	return( f.toString());
	})
	}, null, 2));
	}
	```

- Run the frida script on the pid [[Frida & Objection cheatsheet]]

***
### Process Exploration
- List devices with frida
	```bash
	frida-ls-devices
	```
- [[r2frida cheatsheet#Start the binary with r2frida]]
- [[r2frida cheatsheet#Explore the binary with r2frida]]
- Explore binary with  objection
	```bash
	objection --gadget sg.vantagepoint.helloworldjni explore
	```
- Explore modules in memory with objection ```memory list modules```
- Dump memory fridump
	```bash
	python3 fridump.py -U sg.vantagepoint.helloworldjni
	```
- Extract strings from dump `strings *`