# Thick Client - Win32
## Check If binary is signed
```powershell
# Using sysinternals sigcheck check all files in folder
.\sigcheck.exe -s "C:\Program Files (x86)\Cisco Systems\Cisco Example Application" > 'C:\work\telecom\Cisco Example Application\sigcheck.txt'

# Using Powershell, More checks than sigcheck but provides 
# Less verbosity
Get-ChildItem "C:\Program Files (x86)\Cisco Systems\Cisco Example Application" -Recurse | ForEach-object {Get-AuthenticodeSignature $_.FullName -erroraction 'silentlycontinue'} | Where-Object {$_.status -ne "Valid" -and $_.status -ne "UnknownError"} | fl *
```

## Check if proper hardening has been applied to binary
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

## High Level Picture
1. Check In-Memory Strings
2.  Loaded DLLs
3.  Handles to open files
4.  Command Line arguments/Working directory

[Process Explorer - Windows Sysinternals | Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)


## Monitor API Calls
### Monitor API calls,  Windows Events
#### Monitor Win32 API calls
[API Monitor: Spy on API Calls and COM Interfaces (Freeware 32-bit and 64-bit Versions!) | rohitab.com](http://www.rohitab.com/apimonitor)

#### Monitor Windows Events
> Utilize filters to hone down on intersting events such as read/write events to files that are used during/after authentication/authorization.

[Process Monitor - Windows Sysinternals | Microsoft Docs](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

## Memory
### Dump Memory and search for data
Using Windows Task Manager, right click the process and click create dump file.

![Pasted image 20210914115012.png](/Screenshots/Pasted%20image%2020210914115012.png)

### Modify Data in Memory
#### Tools
[HxD - Freeware Hex Editor and Disk Editor | mh-nexus](https://mh-nexus.de/en/hxd/)


## Fuzz App with WinAFL
Fuzz the application  for memory corruption vulnerabilities.

[googleprojectzero/winafl: A fork of AFL for fuzzing Windows binaries (github.com)](https://github.com/googleprojectzero/winafl)

[BB-1011 Fuzzing WinAFL - YouTube](https://www.youtube.com/watch?v=m7tJkeW6H58)

[[Fuzzing with WinAFL] Writing Harness for a DLL and fuzzing it with WinAFL - YouTube](https://www.youtube.com/watch?v=XeN3M0sK9GA)

> Writing harness functions might be time-consuming. However, very rewarding once you learn how to do so quickly.

## Check registry for clear-text registry writes
[regshot download | SourceForge.net](https://sourceforge.net/projects/regshot/)
1. Use regshot to snapshot the registry before and after any operation that might have written to the registry.
2. Compare both snapshots for registry changes.

## Traffic Interception
Is clear text traffic transferred?
Can you manipulate traffic?

### Traffic Interception Tools
#### WireShark 
> This can be also used for WinShark

[Decrypt SSL with Wireshark - HTTPS Decryption: Step-by-Step Guide (comparitech.com)](https://www.comparitech.com/net-admin/decrypt-ssl-with-wireshark/)

#### WinShark
> WinShark Makes filtering traffic by process ID possible. Use the `etw.header.ProcessId == 1234` filter. Also, make sure to always run wireshark as admininstrator after installing WinShark

[Wireshark · Go Deep.](https://www.wireshark.org/)
[airbus-cert/Winshark: A wireshark plugin to instrument ETW (github.com)](https://github.com/airbus-cert/Winshark)

1. To capture network traffic using Winshark, you have to simply activate network tracing through netsh:
```batch
netsh.exe trace start capture=yes report=no correlation=no
```

2. And then create an ETW session associated with the Microsoft-Windows-NDIS-PacketCapture provider:
```batch
logman start Winshark-PacketCapture -p "Microsoft-Windows-NDIS-PacketCapture" -rt -ets
```

3. Then launch Wireshark with administrator privileges and select the `Winshark-PacketCapture` interface.

#### Echo Mirage
> Echo Mirage enables interception and modification of traffic

[Echo Mirage: Walkthrough - Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/echo-mirage-walkthrough/)

#### HTTP Proxy
[How to Set Up a Proxy in Windows 10 - dummies](https://www.dummies.com/computers/operating-systems/windows-10/how-to-set-up-a-proxy-in-windows-10/)
[Burp Suite - Application Security Testing Software - PortSwigger](https://portswigger.net/burp)

## Debuggers
[IDA Pro – Hex Rays (hex-rays.com)](https://hex-rays.com/ida-pro/)
[Debugging Using WinDbg Preview - Windows drivers | Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-windbg-preview#:~:text=WinDbg%20Preview%20is%20the%20latest,data%20model%20front%20and%20center.)

## Decompilers
[NationalSecurityAgency/ghidra: Ghidra is a software reverse engineering (SRE) framework (github.com)](https://github.com/NationalSecurityAgency/ghidra)

## Learning Resources
[Practical thick client application penetration testing using damn vulnerable thick client app: An introduction - Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/)

[Introduction to Hacking Thick Clients: Part 1 - the GUI (netspi.com)](https://www.netspi.com/blog/technical/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-1-the-gui/)

[secvulture/dvta: Damn Vulnerable Thick Client App (github.com)](https://github.com/secvulture/dvta)