## Exploits
- Sudo Version Vulnerable to [CVE-2021-3156 sudo Vulnerability Allows Root Privileges (aquasec.com)](https://blog.aquasec.com/cve-2021-3156-sudo-vulnerability-allows-root-privileges) 

***

## Misconfigurations
- Custom Systemd timers

## Setuid binaries
- Look for setuid binaries in places not managed by package manager
- Look for non-default setuid binaries

## Find files owned by user/group
```bash
# Find files owned by user
find /var -user vivek

# Find files owned by group
find /home -group ftpusers
```

***

## Misc
### Using timestamp to identify custom files in directories managed by package manager
#### Manual
- Check timestamp of files in directories managed by package manager to identify files modified by users.
	```bash
	ls -la --time-style=full
	```
- Lots of packages don't recored the milisecond or last part of time stamp. If u interact with it that part isn't zereod out. 
- Check for [[Linux/Misc#Linux Directories]] modified by user whom are supposed to be managed by package manager
#### Automated
```bash
#!/bin/bash
paths=$(echo $PATH | sed 's/:/ /g')
for i in $paths; do ls -la --time-style=full $i | grep -v '\-\>\|00000' 2>/dev/null ; done
```
### Check out Config files in their [[Linux/Misc#Config Files Default Locations| Default Locations]]
***
## Docker
- Check `ls -la  /` to see if there is any `docker.env` file
- Check out the running app config files
- Use [[Linux/Priv Esc/Tools#Docker]]
***
## Brute force suing to accounts
[hemp3l/sucrack: brute-forcing su for fun and possibly profit (github.com)](https://github.com/hemp3l/sucrack)
