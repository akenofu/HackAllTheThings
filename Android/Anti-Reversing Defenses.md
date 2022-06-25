# Root Detection
## Identification
### SafetyNet
#### Identification
- Search for `SafetyNetApi.attest`
#### Response
- In broad terms, `basicIntegrity` gives you a signal about the general integrity of the device and its API.
- Devices that will fail `ctsProfileMatch` include the following:
	-   Devices that fail `basicIntegrity`
	-   Devices with an unlocked bootloader
	-   Devices with a custom system image (custom ROM)
	-   Devices for which the manufacturer didn't apply for, or pass, Google certification
	-   Devices with a system image built directly from the Android Open Source Program source files
	-   Devices with a system image distributed as part of a beta or developer preview program (including the Android Beta Program)
#### Recommendations when using SafetyNetApi.attest
- Trust APK information (`apkPackageName`, `apkCertificateDigestSha256` and `apkDigestSha256`) only if the value of `ctsProfileMatch` is true.
- The entire JWS response should be sent to your server, using a secure connection, for verification. It isn't recommended to perform the verification directly in the app because, in that case, there is no guarantee that the verification logic itself hasn't been modified
## Programmatic Detection
### File existence checks
- Checking for files typically found on rooted devices such as
	```bash
	/system/app/Superuser.apk
	/system/etc/init.d/99SuperSUDaemon
	/dev/com.koushikdutta.superuser.daemon/
	/system/xbin/daemonsu
	```
- Checking for binaries found on rooted devices
	```bash
	/sbin/su  
	/system/bin/su  
	/system/bin/failsafe/su  
	/system/xbin/su  
	/system/xbin/busybox  
	/system/sd/xbin/su  
	/data/local/su  
	/data/local/xbin/su  
	/data/local/bin/su
	```
- Checking if `su` is in path using java
	```java
	    public static boolean checkRoot(){
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }
	```
- File checks using native code
	```cpp
	jboolean Java_com_example_statfile(JNIEnv * env, jobject this, jstring filepath) {
	jboolean fileExists = 0;
	jboolean isCopy;
	const char * path = (*env)->GetStringUTFChars(env, filepath, &isCopy);
	struct stat fileattrib;
	if (stat(path, &fileattrib) < 0) {
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat error: [%s]", strerror(errno));
	} else
	{
	__android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat success, access perms: [%d]", fileattrib.st_mode);
	return 1;
	}

	return 0;
	}
	```
- Executing su and other commands/files:  attempting to execute it through `Runtime.getRuntime.exec` method. An IOException will be thrown if `su` is not on the PATH. 
### Checking running processes
- Running processes can be enumerated with the `ActivityManager.getRunningAppProcesses` and `manager.getRunningServices` APIs, the `ps` command, and browsing through the `/proc` directory.
- Example:
	    
	```java
	  public boolean checkRunningProcesses() {
      boolean returnValue = false;
      // Get currently running application processes
      List<RunningServiceInfo> list = manager.getRunningServices(300);

      if(list != null){
        String tempName;
        for(int i=0;i<list.size();++i){
          tempName = list.get(i).process;

          if(tempName.contains("supersu") || tempName.contains("superuser")){
            returnValue = true;
          }
        }
      }
      return returnValue;
    }
	```
### Checking installed app packages
- Check packages belonging to popular rooting tools
	 ```bash
	 com.thirdparty.superuser
	eu.chainfire.supersu
	com.noshufou.android.su
	com.koushikdutta.superuser
	com.zachspong.temprootremovejb
	com.ramdroid.appquarantine
	com.topjohnwu.magisk
	```
### Checking for writable partitions and system directories
Unusual permissions on system directories may indicate a customized or rooted device. Although the system and data directories are normally mounted read-only, you'll sometimes find them mounted read-write when the device is rooted. Look for these filesystems mounted with the "rw" flag or try to create a file in the data directories.
### Checking for custom Android builds
- Checking for signs of test builds and custom ROMs is also helpful. One way to do this is to check the BUILD tag for test-keys, which normally [indicate a custom Android image](https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion//). [Check the BUILD tag as follows](https://www.joeyconway.com/blog/2014/03/29/android-detect-root-access-from-inside-an-app/):

	```java
	private boolean isTestKeyBuild()

	{

	String str = Build.TAGS;

	if ((str != null) && (str.contains("test-keys")));

	for (int i = 1; ; i = 0)

	return i;

	}
	```

- Missing Google Over-The-Air (OTA) certificates is another sign of a custom ROM: on stock Android builds, [OTA updates Google's public certificates](https://blog.netspi.com/android-root-detection-techniques/).

## Bypassing Root Detection
- Run execution traces with jdb, [DDMS](https://developer.android.com/studio/profile/monitor), `strace`, and/or kernel modules to find out what the app is doing.
- Renaming binaries
- Unmounting `/proc` to prevent reading of process lists. Sometimes, the unavailability of `/proc` is enough to bypass such checks.
- Using Frida or Xposed to hook APIs on the Java and native layers. This hides files and processes, hides the contents of files, and returns all kinds of bogus values that the app requests.
- Patching the app to remove the checks.

## Effectiveness Assessment
-   Multiple detection methods are scattered throughout the app (as opposed to putting everything into a single method).
-   The root detection mechanisms operate on multiple API layers (Java APIs, native library functions, assembler/system calls).
- Can the mechanisms be easily bypassed with standard tools, such as RootCloak?
- Is static/dynamic analysis necessary to handle the root detection?
- Do you need to write custom code?
- How long did successfully bypassing the mechanisms take?
-  What is your assessment of the difficulty of bypassing the mechanisms?

***

# Testing Anti-Debugging Detection
## JDWP Anti-Debugging
### Checking the Debuggable Flag in ApplicationInfo
```java
  public static boolean isDebuggable(Context context){

	return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

}
```
### isDebuggerConnected
```java
   public static boolean detectDebugger() {
	return Debug.isDebuggerConnected();
}
```
or via native code
```cpp
JNIEXPORT jboolean JNICALL Java_com_test_debugging_DebuggerConnectedJNI(JNIenv * env, jobject obj) {
if (gDvm.debuggerConnected || gDvm.debuggerActive)
	return JNI_TRUE;
return JNI_FALSE;
}
```
### Timer Checks
`Debug.threadCpuTimeNanos` indicates the amount of time that the current thread has been executing code. Because debugging slows down process execution, [you can use the difference in execution time to guess whether a debugger is attached](https://www.yumpu.com/en/document/read/15228183/android-reverse-engineering-defenses-bluebox-labs).
```java
static boolean detect_threadCpuTimeNanos(){
long start = Debug.threadCpuTimeNanos();

for(int i=0; i<1000000; ++i)
continue;

long stop = Debug.threadCpuTimeNanos();

if(stop - start < 10000000) {
return false;
}
else {
return true;
}
}
```
### Messing with JDWP-Related Data Structures
 the global virtual machine state is accessible via the `DvmGlobals` structure. The global variable gDvm holds a pointer to this structure. `DvmGlobals` contains various variables and pointers that are important for JDWP debugging and can be tampered with.
```cpp
struct DvmGlobals {
/*
 * Some options that could be worth tampering with :)
 */

bool        jdwpAllowed;        // debugging allowed for this process?
bool        jdwpConfigured;     // has debugging info been provided?
JdwpTransportType jdwpTransport;
bool        jdwpServer;
char*       jdwpHost;
int         jdwpPort;
bool        jdwpSuspend;

Thread*     threadList;

bool        nativeDebuggerActive;
bool        debuggerConnected;      /* debugger or DDMS is connected */
bool        debuggerActive;         /* debugger is making requests */
JdwpState*  jdwpState;

};
```
For example, [setting the gDvm.methDalvikDdmcServer\_dispatch function pointer to NULL crashes the JDWP thread](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/AndroidREnDefenses201305.pdf):
```cpp
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```
You can disable debugging by using similar techniques in ART even though the gDvm variable is not available. The ART runtime exports some of the vtables of JDWP-related classes as global symbols (in C++, vtables are tables that hold pointers to class methods). This includes the vtables of the classes `JdwpSocketState` and `JdwpAdbState`, which handle JDWP connections via network sockets and ADB, respectively. You can manipulate the behavior of the debugging runtime [by overwriting the method pointers in the associated vtables](https://web.archive.org/web/20200307152820/https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art) (archived).

One way to overwrite the method pointers is to overwrite the address of the function `jdwpAdbState::ProcessIncoming` with the address of `JdwpAdbState::Shutdown`. This will cause the debugger to disconnect immediately.

### Traditional Anti-Debugging
#### Checking TracerPid
When you debug an app and set a breakpoint on native code, Android Studio will copy the needed files to the target device and start the lldb-server which will use `ptrace` to attach to the process. From this moment on, if you inspect the [status file](http://man7.org/linux/man-pages/man5/proc.5.html) of the debugged process (`/proc/<pid>/status` or `/proc/self/status`), you will see that the "TracerPid" field has a value different from 0, which is a sign of debugging.

> Remember that **this only applies to native code**. If you're debugging a Java/Kotlin-only app the value of the "TracerPid" field should be 0.

Manually check the value of TracerPid with ADB:
```bash
$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271      11839 11837   14024   4548 poll_schedule_timeout 0 S lldb-server
```

#### Using Fork and ptrace
You can prevent debugging of a process by forking a child process and attaching it to the parent as a debugger via code similar to the following simple example code:
```cpp
void fork_and_attach()
{
  int pid = fork();

  if (pid == 0)
    {
      int ppid = getppid();

      if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
          waitpid(ppid, NULL, 0);

          /* Continue the parent process */
          ptrace(PTRACE_CONT, NULL, NULL);
        }
    }
}
```
With the child attached, further attempts to attach to the parent will fail. We can verify this by compiling the code into a JNI function and packing it into an app we run on the device.

#### Fork and ptrace Bypasses
You can easily bypass this failure, however, by killing the child and "freeing" the parent from being traced. You'll therefore usually find more elaborate schemes, involving multiple processes and threads as well as some form of monitoring to impede tampering. Common methods include
-   forking multiple processes that trace one another,
-   keeping track of running processes to make sure the children stay alive,
-   monitoring values in the `/proc` filesystem, such as TracerPID in `/proc/pid/status`.

# Bypassing Debugger Detection
- Patching the anti-debugging functionality: Disable the unwanted behavior by simply overwriting it with NOP instructions.
- Using Frida or Xposed to hook APIs on the Java and native layers: manipulate the return values of functions such as `isDebuggable` and `isDebuggerConnected` to hide the debugger.
- 