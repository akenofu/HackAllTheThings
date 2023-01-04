### Determine Entry Point
Sorted by precedence (if possible)
1. Deeplinks with/out url schemes
2. LauncherActiviy
3. Application Subclass

***

### Permissions  
- SD Card Storage
	```
	uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
	```
***

- Check the Imports in the classess to get an idea of what the class does
- Grep for key words using command line tools [[Android/Sensitive Data Disclosure/Local Storage|Search for Sensitive Data using Static Analysis]]
- Check for outdated libraries