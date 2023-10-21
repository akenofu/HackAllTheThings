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
## Race Conditions

Use Inotify to hook to system file creation events and exploit race conditions
[How to Use inotify API in C Language – Linux Hint](https://linuxhint.com/inotify_api_c_language/)

[Sample Code](/Code%20Snippets/C%20Inotify%20Hooking%20Library.md) to hook to file events.

---

## Greb For passwords by entroy
Password policies enforce users to create passwords with high entropies. Entropy is a measure of randomness 😶‍🌫️. A high entropy password is a password with the following charchteristics:
- No repeating sequences of characters
- Special characters
- Upper case
- Lowercase

```bash
for i in $(grep -oP "('.*?')" -R --no-filename .); do x=$(echo -n $i | ent | grep Entropy | awk '{print $3}'); echo "$x $i"; done | sort -n
```

---

## Misc
### Using timestamp to identify custom files in directories managed by package manager
#### Manual
- Check timestamp of files in directories managed by package manager to identify files modified by users.
	```bash
	ls -la --time-style=full
	```
- Lots of packages don't recored the milisecond or last part of time stamp. If u interact with it that part isn't zereod out. 
- Check for [[Linux/Miscellaneous#Linux Directories]] modified by user whom are supposed to be managed by package manager
#### Automated
```bash
#!/bin/bash
paths=$(echo $PATH | sed 's/:/ /g')
for i in $paths; do ls -la --time-style=full $i | grep -v '\-\>\|00000' 2>/dev/null ; done
```
### Check out Config files in their [[Linux/Miscellaneous#Config Files Default Locations| Default Locations]]
***
## Docker
- Check `ls -la  /` to see if there is any `docker.env` file
- Check out the running app config files
- Use [[Linux/Priv Esc/Tools#Docker]]
***
## Brute force suing to accounts
[hemp3l/sucrack: brute-forcing su for fun and possibly profit (github.com)](https://github.com/hemp3l/sucrack)

## Creds in files
### AWS
```bash
~/.aws/credentials
```

---
# Tools
### Docker
[stealthcopter/deepce: Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE) (github.com)](https://github.com/stealthcopter/deepce)

### Linux
[privilege-escalation-awesome-scripts-suite/linPEAS at master · carlospolop/privilege-escalation-awesome-scripts-suite (github.com)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)