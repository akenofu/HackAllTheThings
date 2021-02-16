### Commands
Guest User and null authentication
`smbmap -u anonymous -p anonymous -H 10.10.10.172`
`smbmap -u '' -p '' -H 10.10.10.172`

Password Brute Forcing
`crackmapexec smb 10.10.10.172 -u /root/users.lst -p /root/passwords.lst`