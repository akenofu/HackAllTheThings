## Check If binary is signed
```powershell
# Using sysinternals sigcheck check all files in folder
.\sigcheck.exe -s "C:\Program Files (x86)\Cisco Systems\Cisco Jabber\" > 'C:\work\telecom\Cisco Jabber\sigcheck.txt'

# Using Powershell, More Inclusive than sigcheck but provides 
# Less verbosity
Get-ChildItem "C:\Program Files (x86)\Cisco Systems\Cisco Jabber\" -Recurse | ForEach-object {Get-AuthenticodeSignature $_.FullName -erroraction 'silentlycontinue'} | Where-Object {$_.status -ne "Valid" -and $_.status -ne "UnknownError"} | fl *
```

## Check if proper hardening has been applied to binary
[NetSPI/PESecurity: PowerShell module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode. (github.com)](https://github.com/NetSPI/PESecurity)
```powershell
# Import module
Import-Module .\Get-PESecurity.psm1

# Check a directory for DLLs & EXEs recrusively 
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Jabber"  -recursive | Export-Csv PESecurity.csv

# Txt file output
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Jabber"  -recursive > .\PESecurity.txt

# Bulk Get POCs for files
Get-PESecurity -directory "C:\Program Files (x86)\Cisco Systems\Cisco Jabber"  -Recursive | Where-Object {$_.ControlFlowGuard -ne "True" } | ForEach-Object {write-output $_.FileName} > 'C:\work\telecom\Cisco Jabber\ControlFlowGuardModules.txt'
```

## Monitor API Calls
### APIMonitor
// TODO

### Dump Memory and search for data
// TODO

## Fuzz App with WinAFL
// TODO

## Check registry for registry writes
// TODO