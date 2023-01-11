# Frida Set up
## Install
1. Download `frida_16.0.8_iphoneos-arm.deb`
2. Transfer package to mobile with scp
3. Install the package with `dpkg -i frida_16.0.8_iphoneos-arm.deb`


## Run
On your IPhone
```bash
ssh 192.168.114.53

# -D is daemon mode
./frida/usr/sbin/frida-server -l 0.0.0.0:3039 -D 
```

On your testing host
```bash
frida-ps -a -R 192.168.114.153:3039

objection -N -h 192.168.114.153 -p 3039 -d --gadget <application_name> explore 
```

