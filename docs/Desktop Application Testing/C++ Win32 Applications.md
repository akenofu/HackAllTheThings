# C++ Win32 Applications
### Static Analysis
- Check If binary is signed
```powershell
# Using sysinternals sigcheck check all files in folder
.\sigcheck.exe -s "C:\Program Files (x86)\Cisco Systems\Cisco Example Application" > 'C:\work\telecom\Cisco Example Application\sigcheck.txt'

# Using Powershell, More checks than sigcheck but provides 
# Less verbosity
Get-ChildItem "C:\Program Files (x86)\Cisco Systems\Cisco Example Application" -Recurse | ForEach-object {Get-AuthenticodeSignature $_.FullName -erroraction 'silentlycontinue'} | Where-Object {$_.status -ne "Valid" -and $_.status -ne "UnknownError"} | fl *
```
 - Check if proper hardening has been applied to binary
[NetSPI/PESecurity: PowerShell module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode. (github.com)](https://github.com/NetSPI/PESecurity)
```powershell
# Import module
Import-Module .\Get-PESecurity.psm1

# Check a directory for DLLs & EXEs recrusively 
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Example Application"  -recursive | Export-Csv PESecurity.csv

# Txt file output
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Example Application"  -recursive > .\PESecurity.txt

# Bulk Get POCs for files
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Example Application"  -Recursive | Where-Object {$_.ControlFlowGuard -ne "True" } | ForEach-Object {write-output $_.FileName} > 'C:\work\telecom\Cisco Example Application\ControlFlowGuardModules.txt'
```

**Intersting Stuff to search for during static and dynamic analysis**

- Currently logged in user's token, password, or username in memory. 
- Any intersting endpoints and urls (check the regexes below for some inspiration)
- Mentions of passwords, secerets, tokens etc...
- Local Servers spinned up by thick client for interprocess comunciation or external communication.

```bash
# Identify Local Servers spinned up by the thick client
grep -oa -RiP '(tcp|udp|pipe|local|port)[a-zA-Z0-9_]{0,20}[:"=][^0\Wa-zA-Z_\-][\d]{2,5}[^\d]' .
```

**Check for Misconfigured Directory Permissions using icacls**
```powershell
# This should show if any folder/file has a unique permission for both the Built in users and authenticated user groups.
# A correctly configured folder/file permissions should be 
# Access : NT AUTHORITY\Authenticated Users Allow  ReadAndExecute, Synchronize
#          BUILTIN\Users Allow  ReadAndExecute, Synchronize
#          BUILTIN\Users Allow  -1610612736
dir '.\Windows\DummyApplication' -Recurse | Get-Acl | fl | findstr 'Users'|  select -Unique
```

---


### Analysis

- Dump Memory and search for data using Windows Task Manager, right click the process and click create dump file.

	![](/Screenshots/Pasted%20image%2020210914115012.png)
	If the applications spawn multiple sub processes, use the below powershell script to create an array of those subprocess ids and dump their memory.

	```powershell
	 function Dump-ProcessesMemoryByName($regex) {
	 $ids = (Get-Process -Name $regex | ForEach-Object id)
	 New-Item -Name "dump" -ItemType "directory" 
	 foreach($id in $ids) {
	    .\procdump.exe $id -accepteula -ma "dump\$id"
		 }
	 }
	
	Dump-ProcessesMemoryByName('*edge*')
	```

- Check Loaded DLLs using [Process Explorer - Windows Sysinternals | Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
-   Identify Handles to open files
-  Command Line arguments/Working directory
- Monitor Win32 API calls & Windows Events using [API Monitor: Spy on API Calls and COM Interfaces (Freeware 32-bit and 64-bit Versions!) | rohitab.com](http://www.rohitab.com/apimonitor)
-  Monitor Windows Events using [Process Monitor - Windows Sysinternals | Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

> Utilize filters to hone down on intersting events such as read/write events to files that are used during/after authentication/authorization.


- Check registry for clear-text registry writes using [regshot | SourceForge.net](https://sourceforge.net/projects/regshot/)
	1. Use regshot to snapshot the registry before and after any operation that might have written to the registry.
	2. Compare both snapshots for registry changes.


### In Disk/Memory Manipulation
- Modify the binary using [HxD - Freeware Hex Editor and Disk Editor | mh-nexus](https://mh-nexus.de/en/hxd/)


### Fuzzing
Fuzz the application using WinAFL  for memory corruption vulnerabilities.
- [googleprojectzero/winafl: A fork of AFL for fuzzing Windows binaries (github.com)](https://github.com/googleprojectzero/winafl)
- [[Fuzzing With WinAFL] How to fuzz a simple C program with WinAFL - YouTube](https://www.youtube.com/watch?v=Va_Wtxf3DMc&t=760s)
- [BB-1011 Fuzzing WinAFL - YouTube](https://www.youtube.com/watch?v=m7tJkeW6H58)
- [Fuzzing with WinAFL Writing Harness for a DLL and fuzzing it with WinAFL - YouTube](https://www.youtube.com/watch?v=XeN3M0sK9GA)

> Writing harness functions might be time-consuming. However, very rewarding once you learn how to do so quickly.


### Traffic Interception
- Is clear text traffic transferred?
- Can you manipulate traffic?

> You can use one or many of these techniques in conjuncture to read/manipulate network traffic. My personal favorite is fiddler to intercept the traffic and forward it to Burp Suite in combination with Burp Suite custom proxy rules to narrow down the traffic to the application specific traffic as much as possible without the noise generated by the OS and other random applications on the host.


#### Important Proxying Notes 
**Windows Global System Proxy**
Fidler isn't a sniffer - it's a proxy. Unless you can get the offending application to use a proxy none of its traffic is going to run through Fiddler. Java applications don't use the operating system's SSL "stack", so interception utilities that shim into the Windows SSL stack aren't going to be helpful either. Presumably the remote servers aren't running an SSL stack that's easy to snoop inside (since you say they're running Tomcat, and also not likely using the OS SSL stack).

[windows - Log an Application's Network Activity with Process Monitor and/or Fiddler or something else - Server Fault](https://serverfault.com/questions/241879/log-an-applications-network-activity-with-process-monitor-and-or-fiddler-or-som)

**AppContainers**
Some metro style applications run run inside isolated processes known as "**AppContainers.**" By default, AppContainers are forbidden from sending network traffic to the local computer (loopback). This is, of course, problematic when debugging with Fiddler, as Fiddler is a proxy server which runs on the local computer.  Fiddler has a GUI tool that allows you to very easily reconfigure an AppContainer to enable loopback traffic.

[AppContainer Isolation - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
[Revisiting Fiddler and Win8+ Immersive applications – Fiddler Web Debugger (archive.org)](https://web.archive.org/web/20171109101204/https://blogs.msdn.microsoft.com/fiddler/2011/12/10/revisiting-fiddler-and-win8-immersive-applications/)


#### WireShark 
> This can be also used for WinShark

[Decrypt SSL with Wireshark - HTTPS Decryption: Step-by-Step Guide (comparitech.com)](https://www.comparitech.com/net-admin/decrypt-ssl-with-wireshark/)

#### WinShark
It's possible to use WireShark to filter network traffic by process ID using the WinShark plugin. In the simplest terms this plugin corelates ETW events with the traffic produced.

> WinShark Makes filtering traffic by process ID possible. Use the `winshark.header.ProcessId == 1234` filter. Also, make sure to always run wireshark as admininstrator after installing WinShark

You can find the installation instructions in the README on their github:
[airbus-cert/Winshark: A wireshark plugin to instrument ETW (github.com)](https://github.com/airbus-cert/Winshark)



**Script to generate a wireshark filters for all subprocess of  a process**
```powershell
# N.b. if application keep spawning processes this is rendered useless as your filters list is outdated.

function Get-ChildProcesses ($ParentProcessId) {
    $filter = "parentprocessid = '$($ParentProcessId)'"
    Get-CIMInstance -ClassName win32_process -filter $filter | Foreach-Object {
            $_
            if ($_.ParentProcessId -ne $_.ProcessId) {
                Get-ChildProcesses $_.ProcessId
            }
        }
}

function Generate-WinSharkFilters($ParentProcessId){
	$pids = (Get-ChildProcesses($ParentProcessId) |  ForEach-Object { $_.ProcessId } )
	$pids += $ParentProcessId
	$StrPids = $pids -join '|'
	write-host "string(winshark.header.ProcessId) matches '$StrPids'"
}

Generate-WinSharkFilters('5473')
```


**Usage**

1. To capture network traffic using Winshark , you have to simply activate network tracing through netsh:
```batch
netsh.exe trace start capture=yes report=no correlation=no
```

2. And then create an ETW session associated with the Microsoft-Windows-NDIS-PacketCapture provider:
```batch
logman start Winshark-PacketCapture -p "Microsoft-Windows-NDIS-PacketCapture" -rt -ets
```

3. Then launch Wireshark with **administrator privileges** and select the `Winshark-PacketCapture` interface.

#### Fiddler

```VBSCRIPT
public static function IsInternalHost(oSession: Session) : Boolean
{
    var hostname = oSession.hostname;
    if(!String.IsNullOrWhiteSpace(hostname)){
        try{
            var testIp = System.Net.Dns.GetHostEntry(hostname).AddressList[0];
            
            //oSession.RequestHeaders.Add("debugme",testIp.ToString());
            if(System.Net.IPAddress.IsLoopback(testIp) || hostname.Equals("::1")) return true;
    
            var ip = testIp.GetAddressBytes();
    
            switch (ip[0])
            {
                case 10:
                case 127:
                    return true;
                case 172:
                    return ip[1] >= 16 && ip[1] < 32;
                case 192:
                    return ip[1] == 168;
            }
        }catch(error){
            
        }
    }
    
    return false;
}


 static function OnBeforeRequest(oSession: Session) {
        if ( oSession.HostnameIs("burp") || 
            oSession.hostname.ToLower().EndsWith("victim.com") || oSession.hostname.ToLower().EndsWith("attacker.com") || 
            oSession.hostname.ToLower().EndsWith("wow.cc") || oSession.hostname.ToLower().EndsWith("awesome.cc") ||
            IsInternalHost(oSession) ||
            Uri.CheckHostName(oSession.hostname) == null || Uri.CheckHostName(oSession.hostname).Equals(UriHostNameType.Unknown) ||
            oSession.hostname.ToLower().Contains("target.net")
            ) 
            {
            oSession["X-OverrideGateway"] = "127.0.0.1:8080";  
        } 

```

#### MITM Proxy 
TBD

#### Windows HTTP Proxy
- [How to Set Up a Proxy in Windows 10 - dummies](https://www.dummies.com/computers/operating-systems/windows-10/how-to-set-up-a-proxy-in-windows-10/)
- [Burp Suite - Application Security Testing Software - PortSwigger](https://portswigger.net/burp)

### Debuggers
- [IDA Pro – Hex Rays (hex-rays.com)](https://hex-rays.com/ida-pro/)
- [Debugging Using WinDbg Preview - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-windbg-preview#:~:text=WinDbg%20Preview%20is%20the%20latest,data%20model%20front%20and%20center.)

### Decompilers
- [NationalSecurityAgency/ghidra: Ghidra is a software reverse engineering (SRE) framework (github.com)](https://github.com/NationalSecurityAgency/ghidra)


---
## Learning Resources

- [Practical thick client application penetration testing using damn vulnerable thick client app: An introduction - Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/)
- [Introduction to Hacking Thick Clients: Part 1 - the GUI (netspi.com)](https://www.netspi.com/blog/technical/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-1-the-gui/)
- [secvulture/dvta: Damn Vulnerable Thick Client App (github.com)](https://github.com/secvulture/dvta)
- [Breaking Docker Named Pipes SYSTEMatically: Docker Desktop Privilege Escalation – Part 1 (cyberark.com)](https://www.cyberark.com/resources/threat-research-blog/breaking-docker-named-pipes-systematically-docker-desktop-privilege-escalation-part-1)