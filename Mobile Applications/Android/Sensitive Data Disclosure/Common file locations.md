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