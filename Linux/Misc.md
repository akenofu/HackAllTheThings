## Linux Directories
- `/usr/bin` managed by package manager
- `/usr/local/bin` managed by user


## Linux File/Folder Permissions
### Extended Permissions
Files ending with `+` indicate extended permissions `-rw-r-----+`
```bash
# Enumerate Extended Permissions
lsattr bucket/app
getfacl bucket/app
```