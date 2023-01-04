# Backups
- Check AndroidManifest.xml to see if adb can take local backups, Check for `android:allowBackup` set to false, default is true, Note if device is encrypted backup is encryped too.

- Use [[adb Cheatsheet#Local Backups]] to navigate those backups
---
# Common File Locations
-	Shared resources 
 	`res/values/strings.xml`
	Example
	```xml
	<resources>
	<string name="app_name">SuperApp</string\>
	<string name="hello_world">Hello world!</string\>
	<string name="action_settings">Settings</string\>
	<string name="secret_key">My_Secret_Key</string\>
	</resources>
	```

- build configs
	`local.properties` or `gradle.properties`
	Example
	```
	buildTypes {
	debug {
	minifyEnabled true
	buildConfigField "String", "hiddenPassword", "\\"${hiddenPassword}\\""
	} }
	```


- Unencrypted Shared Preferences
`/data/data/<package-name>/shared_prefs`

- Misconfigured Firebase Real-time databases
`https://_firebaseProjectName_.firebaseio.com/.json`

- Unencrypted Realm database
`/data/data/<package-name>/files/` 
By default  By default, the file extension is `realm` and the file name is `default`. Inspect the Realm database with  [Realm: Realm is a mobile database: a replacement for SQLite & ORMs. SDKs for Swift, Objective-C, Java, Kotlin, C#, and JavaScript. (github.com) ](https://github.com/realm/) 
---
# Content Providers
### check AndroidManifest.xml for  `<provider>` tags
-   expored = true ?  
    `android:exported`
-   Has an intent filter  
    `<intent-filter>`
-   Protected by permissions ?  
    `android:permission`
-   is Protection Level signature ? (If so only apps signed with same key can access)
    `android:protectionLevel`
	***
### Inspect code for keywords
	`android.content.ContentProvider`
	 `android.database.Cursor`
	 `android.database.sqlite`
	 `.query`
	 `.update`
	 `.delete`
***
### Exploit using [[drozer cheatsheet]]
---
# Generic Ideas
## Data Storage

#### Identify Storage Mechanisms used by the application ? 
- Does application store data on SDCard
- Are encryptian keys hardcoded ?
- is the Key Derivation Function(KDF) accessible for us ? 
	- Does the app user predictable identifiers
		- Password reusability
		- Weak and predictable
		- Identifiers which are accessible to other applications 
- Are the keys stored publicly ?
- Does the application/algorithm zero out passwords stored in memory

***

#### Is sensitive data stored in Process Memory
- Are secerets zero'd out after being used
	- does the compilter optimize the code and remove the zero'ing operation ?
- Are immutable data-types used to store secerets ? (They store data on heap)
- Are complex data-types used to store secerets ? 

***
---
# Keyboard Cache
- is Keyboard Cache Is Disabled for Text Input Fields
	```xml
	<EditText
	android:id="@+id/KeyBoardCache"
	android:inputType="textNoSuggestions" />
	```

---
# Local Storage
### Check keywords/API calls that used to store data
- Keywords/Flags
`MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`
- API calls
`SharedPreferences`
`FileOutPutStream`
`getExternal*`
`getWritableDatabase`
`getReadableDatabase`
`getCacheDir` or `getExternalCacheDirs`

---
# Logs
### Check keywords/API calls that used to log data
- Keywords/Flags
```Java System.out.print```
`System.err.print`
`logfile`
`logging`
`logs`
- API calls
`android.util.Log`
`Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`
`Logger`
- Tools
[Java Obfuscator and Android App Optimizer | ProGuard (guardsquare.com)](https://www.guardsquare.com/en/products/proguard)
- Dynamically constructed strings for logs not remove in build
	Example
	`Log.v("Private key tag", "Private key [byte format\]: " + key);`
	`Log.v("Private key tag", new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());`
	
	### Check logs in console
	- Check if developers used `System.out.println` or `printStackTrace` for logging by checking logcat. Check [[adb Cheatsheet#Logs]] for more details

---

# User interface
- Check AndroidManifest.xml to make sure input fields are masked password
		`android:inputType="textPassword"`
- Check that `FLAG_SECURE` has been set for important windows
	   ```Java
		getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
						WindowManager.LayoutParams.FLAG_SECURE);

		setContentView(R.layout.activity_main);
		
		
- To exploit checkout https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05d-testing-data-storage#dynamic-analysis-7

