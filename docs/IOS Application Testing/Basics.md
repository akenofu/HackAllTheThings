# Basics
```bash
# Get Device UDID
idevice_id -l

# SSH to device
# Default creds are root:alpine and mobile:alpine
ssh root@192.168.178.94 

# Transfer files from Phone to desktop
scp root@localhost:/tmp/hi.txt .

# List installed applications
ideviceinstaller -l
```
# Install Fake IPAs
1. Inside, Sileo add `https://cydia.akemi.ai/` as source.
2. From the new packages install appinst and appsync Unified
3. Inside an SSH shell `appinst /var/root/<application_name>.ipa`

**Alternatively,**
Use [Sideloadly - iOS & Apple Silicon Sideloading](https://sideloadly.io/)


