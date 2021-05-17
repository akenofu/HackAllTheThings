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

