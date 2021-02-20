- Anonymous Login
`smbmap -u anonymous -p anonymous -H 10.10.10.172`
- null authentication
`smbmap -u '' -p '' -H 10.10.10.172`
- Password Brute Forcing
`crackmapexec smb 10.10.10.172 -u /root/users.lst -p /root/passwords.lst`