# SMB
## Gaining Access
### Test for Null authentication
```bash
# Using crackmapexec
crackmapexec smb 10.10.10.219 -u '' -p '' --shares

# Using SmbClient
smbclient -N //10.10.10.219/kanban

# Using SmbMap
smbmap -u '' -p '' -H 10.10.10.172
```

### Test for anonymous/guest login
```bash
# Using Smbmap
smbmap -u anonymous -p anonymous -H 10.10.10.172
```

### Password Brute Forcing
```bash
crackmapexec smb 10.10.10.172 -u /root/users.lst -p /root/passwords.lst
```

***
## Enumeration
```bash
# Enum users
crackmapexec smb 10.10.10.219 -u '' -p '' --users

# Enum Password Policy
crackmapexec smb 10.10.10.219 -u '' -p '' --pass-pol

# Enum files on share and their creation/modification dates
crackmapexec smb 10.10.10.219 -u '' -p '' -M spider_plus
```

***

## Exploitation
### Download all files from share
```bash
# Using smbclient
smbclient -N //10.10.10.219/kanban
recurse ON
prompt OFF
mget *
```