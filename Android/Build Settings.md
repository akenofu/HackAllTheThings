### Application Signature
- Verify Signature 
`apksigner verify --verbose Desktop/example.apk`
- View signing certificate content
`jarsigner -verify -verbose -certs example.apk`
- Make sure app is not deployed with your internal testing certificates

***

### Testing Whether the App is Debuggable
- Check AndroidManifest.xml for `android:debuggable`
- [[drozer cheatsheet#Exported IPC components|Dynamic Anaylsis with drozer to find if application is debuggable from attack surface]]
- [[drozer cheatsheet#Scan for all debuggable applications on a device]]
- [[adb Cheatsheet#Application Debuggable|Use adb to execute commands in context of app]]
- [[adb Cheatsheet#Application Debuggable|Debug app with jdb]]


### Test for Debugging Symbols
- Static analysis should be used to verify debugging symbols.


### Testing for Debugging Code and Verbose Error
- Determine wether `StrictMode` is enabled, To disable `StrictMode`, `DEVELOPER_MODE` must be disabled for the release build
`StrictMode.setThreadPolicy` or `StrictMode.setVmPolicy`
- Search for calls to 
`detectDiskWrites()` or `detectDiskReads()` or `detectNetwork()`
`penaltyLog()` or `penaltyDeath()` or `penaltyDialog()`
- Check logcat for `StrictMode` output

***

### Checking for Weaknesses in Third Party Libraries
- Use OWASP Dependency checker.
- Is the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched.
- Does Is the vulnerability actually affects the application?
- When Dexguard or [ProGuard](/mobile-security-testing-guide/appendix/0x08-testing-tools#proguard) are applied properly, then version information about the library is often obfuscated
- retrieve the version of the library, either via comments, or via specific methods used in certain versions

#### Detecting the Licenses Used by the Libraries of the Application
- using a plugin which can iterate over the different libraries, such as `License Gradle Plugin`. This plugin can be used by taking the following steps.
In your `build.gradle` file add:
	```
	plugins {
		id "com.github.hierynomus.license-report" version"{license_plugin_version}"
	}
	```
- Now use the commands
`gradle assemble`
`gradle downloadLicenses`
- Check the license-report generated to see whether a copyright notice needs to be included into the app and whether the license type requires to open-source the code of the application.

***

### Testing Exception Handling
- Does application  expose sensitive information while handling exceptions in its UI or log-statements ?
- Make sure that all confidential information handled by high-risk applications is always wiped during execution of the `finally` blocks
- Adding a general exception handler for uncaught exceptions is a best practice 
-  Use Xposed to hook into methods and either call them with unexpected values or overrite existing variables with unexpected values (e.g., null values).
-   Type unexpected values into the Android application's UI fields.
-   Interact with the application using its intents, its public providers, and unexpected values.
-   Tamper with the network communication and/or the files stored by the application.
- The application should never crash

***

### Memory Corruption Bugs
-   In case of native code: use Valgrind or Mempatrol to analyze the memory usage and memory calls made by the code.
-   In case of Java/Kotlin code, try to recompile the app and use it with [Squares leak canary](https://github.com/square/leakcanary).
-   Check with the [Memory Profiler from Android Studio](https://developer.android.com/studio/profile/memory-profiler) for leakage.
-   Check with the [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda), for serialization vulnerabilities.

***

### Make Sure That Free Security Features Are in place
- If source code is provided, check `build.gradle`  for obfuscation settings
`minifyEnabled` and `proguardFiles`
- Are there exception classes in proguard config file
`getDefaultProguardFile('proguard-android.txt')` or default folder `<Android SDK>/tools/proguard/` or file `proguard-rules.pro`
- Decompile code to check if code has been obfuscated
- make sure that class, method, and variable names are not human-readable
