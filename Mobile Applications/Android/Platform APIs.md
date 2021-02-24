## Permissions
- Dump Permissions
	`adb shell dumpsys package com.spotify.music | grep permission`
- Are permissions implemented programmatically?
	```Java
	private static final String TAG = "LOG";
	int canProcess = checkCallingOrSelfPermission("com.example.perm.READ_INCOMING_MSG");
	if (canProcess != PERMISSION_GRANTED)
	throw new SecurityException();
	```
	
- Get Custom Permissions with drozer [[drozer cheatsheet#Permissions]]


### Injection Flaws
#### Content Providers
- Test exposed content providers for SQL injection using [[adb Cheatsheet#Content Provider]]
#### Fragment Injections
- `android:targetSdkVersion` < 19 ?
- Find exported Activities that extend the `PreferenceActivity` class
- Determine whether the method `isValidFragment` has been overridden
#### Url Loading in WebViews
- is `EnableSafeBrowsing` disabled in AndroidManifest.xml
#### Custom URL Schemes
