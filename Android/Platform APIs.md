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

***

## Injection Flaws
### Content Providers
- Test exposed content providers for SQL injection using [[adb Cheatsheet#Content Provider]]
### Fragment Injections
- `android:targetSdkVersion` < 19 ?
- Find exported Activities that extend the `PreferenceActivity` class
- Determine whether the method `isValidFragment` has been overridden
### Url Loading in WebViews
#### is `EnableSafeBrowsing` disabled in AndroidManifest.xml
#### Search for callbacks for overriden `WebViewClient`
- `shouldOverrideUrlLoading` 
	Not called for post reqs. or `XmlHttpRequests` or `<script>` or iframes src)
- `shouldInterceptRequest` 
	- allows the application to return the data from resource requests. If the return value is null, the WebView will continue to load the resource as usual
	- invoked for a variety of URL schemes (e.g., `http(s):`, `data:`, `file:`, etc.)
	- Not called for `javascript:` or `blob:` or `file:///android_asset/` or `file:///android_res/` URLs
	- is url whitelisted with `setSafeBrowsingWhitelist` or warrning callback ignored `onSafeBrowsingHit`

### Custom URL Schemes
#### Test Deep links for
- reflection-based persistence type of data processing
- Using the data for queries
- Using the data to do authenticated actions? Make sure that the user is in an authenticated state before the data is processed
- tampering of the data will influence the result of the calculations without an hmac
#### Find deeplinks in AndroidManifest.xml
- Search for `<intent-filter>`
- Check attributes for hints on their usage
	`<category android:name="android.intent.category.BROWSABLE" />` Indicates it can be opened in browser
- Check if `<intent-filter android:autoVerify="true">` is defined as a hint to it being an App link
- If parameters in deep or app link is used for processing. Is the source verified ?
	```Java
	Intent intent = getIntent();
	if (Intent.ACTION_VIEW.equals(intent.getAction())) {
	  Uri uri = intent.getData();
	  String valueOne = uri.getQueryParameter("keyOne");
	  String valueTwo = uri.getQueryParameter("keyTwo");
	}
	```
- Search for `getIntent` or `getData` usage
#### Testing Deep using
- Open the link in mobile browser
- Send intents to android device using adb

***


### Testing Insecure Configuration of Instant Apps
- Check if it is instant app search for `dist:module dist:instant="true"` in Android Manifest.xml
- Check for entry points `<data android:path="</PATH/HERE>" />`
- Check [Testing for Insecure Configuration of Instant Apps (MSTG-ARCH-1, MSTG-ARCH-7)](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05h-testing-platform-interaction#testing-for-insecure-configuration-of-instant-apps-mstg-arch-1-mstg-arch-7)

***

### Testing for Sensitive Functionality Exposure Through IPC
- Find IPC helpers in AndroidManfiest.xml
	- `<intent-filter>` 
	- `<service>`
	- `<provider>`
	- `<receiver>`
- Find exported components
	- `android:exported="true"`
	- Components declaring `<intent-filter>`
	- Are they protected with correct permissions `android:permission` ir `android:protectionLevel`
- Exploit Exported Components
	- XSS in the android webview?
	- Try to abuse app functionality

#### broadcast recievers
- Search for keywords indicating usage of 
	- `sendBroadcast` or `sendOrderedBroadcast` or `sendStickyBroadcast` 
	- class `android.content.BroadcastReceiver` or class `Context.registerReceiver`
- Are they protected with `android:permission` , otherwise other apps can invoke them

#### Extra Tests
Check [[drozer cheatsheet#Exported IPC components]] for extra tests

***
## Webviews
### Testing JavaScript Execution in WebViews
- Identify used webviews, search for
	`WebView` or `loadUrl` or `setContentView`
- Identify enabled JS in webviews
	`setJavaScriptEnabled`
- Devices running platforms older than Android 4.4 (API level 19) use a version of WebKit that has several security issues 
#### Abusing webviews
- Stored XSS on endpoint ?
- Only files that are in the app data directory should be rendered in a WebView
- avoid MITM attacks
	- all communication is encrypted via TLS
	- the certificate is checked properly
	- the certificate should be pinned

### Testing WebView Protocol Handlers
- Users shouldn't be able to manipulate filename or the path used to load the file
- Search for Keywords related to resource access
`setAllowContentAccess` or `setAllowContentAccess` or `file:///android_asset` or `file:///android_res` or `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`
- Search for where webview is loaded
`webView.loadUrl("file:///android\_asset/filename.html");`
- is the file placed in app asset directory? or sdcard?

### Determining Whether Java Objects Are Exposed Through WebViews 
- Android versions below Android 4.2 (API level 17) as they are [vulnerable to a flaw](https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/) in the implementation of `addJavascriptInterface`
- Check for keywords
`addJavascriptInterface` or `@JavascriptInterface`
or calls
`window.Android.returnString();`
- are urls allowed to access java object whitelisted with `WebView.getUrl`
- if necessary for legacy reasons (e.g. having to support older devices), at least set the minimal API level to 17 in the manifest file of the app


### Testing Object Persistence
#### Search for
#### Serialization
- Search for serilaization indicative keywords `import java.io.Serializable` or `implements Serializable`
#### JSON
- JSON
`import org.json.JSONObject` or `import org.json.JSONArray;`
- GSON 
`import com.google.gson` or `import com.google.gson.annotations` or `import com.google.gson.reflect` or `import com.google.gson.stream` or `new Gson();` or `@Expose` or `@JsonAdapter` or `@SerializedName` or `@Since` or `@Until`
- Jackson
`import com.fasterxml.jackson.core` or `import org.codehaus.jackson`
#### Orm
- OrmLite
`import com.j256.*` or `import com.j256.dao` or `import com.j256.db` or `import com.j256.stmt` or `import com.j256.table`
- SugarORM
	- `import com.github.satyan` or `extends SugarRecord<Type>`
	-  In the AndroidManifest `meta-data` entries with values such as `DATABASE`, `VERSION`, `QUERY_LOG` and `DOMAIN_PACKAGE_NAME`.
	- Make sure that `QUERY_LOG` is set to false.
- GreenDAO
	- `import org.greenrobot.greendao.annotation.Convert` , `import org.greenrobot.greendao.annotation.Entity` , `import org.greenrobot.greendao.annotation.Generated` , `import org.greenrobot.greendao.annotation.Id` , `import org.greenrobot.greendao.annotation.Index` , `import org.greenrobot.greendao.annotation.NotNull` , `import org.greenrobot.greendao.annotation.*` , `import org.greenrobot.greendao.database.Database` , `import org.greenrobot.greendao.query.Query`
- ActiveAndroid
`ActiveAndroid.initialize(<contextReference>);` ,  `import com.activeandroid.Configuration` , `import com.activeandroid.query.*`
- Realm
`import io.realm.RealmObject;` or `import io.realm.annotations.PrimaryKey;`

### Testing for Overlay Attacks
- is the app targeting an android version vulnerable to clickjacking?
- Check views for security controls by searching the keywords
	- `onFilterTouchEventForSecurity` or `android:filterTouchesWhenObscured` or `setFilterTouchesWhenObscured` or `FLAG_WINDOW_IS_OBSCURED` or `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` 
	- properly check the API level that app is targeting and the implications that this has
- Test using these sample pocs [FSecureLABS/tapjacking-poc (github.com)](https://github.com/FSecureLABS/tapjacking-poc) 


### Test enforced updating
- Search for keywords hinting enforced updating `AppUpdateManager` or `Task<AppUpdateInfo>`

### Testing App Notifications
- Can an external app abuse the `NotificationListenerService` to disclose sensitive information
- Identify if notfications are used. Search for keywords `NotificationManager` 