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