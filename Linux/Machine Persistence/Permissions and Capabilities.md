## Set the setuid bit for `sh` or any binary
```bash
# 1. Find where /bin/sh links to
ls -la /bin/sh

# 2. Set the setuid bit for binary
chmod 4755 /bin/dash

# 3. Check if the bit is set
ls -la /bin/dash
```


## Capabilities 
// TODO