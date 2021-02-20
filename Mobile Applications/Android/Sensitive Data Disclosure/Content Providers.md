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