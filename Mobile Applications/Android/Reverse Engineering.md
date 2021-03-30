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
	```
- List loaded native libraries
	```bash
	cat /proc/7894/maps
	```

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
