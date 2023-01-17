# Frida Setup
## Install
1. Download `frida_16.0.8_iphoneos-arm.deb`
2. Transfer package to mobile with scp
3. Install the package with `dpkg -i frida_16.0.8_iphoneos-arm.deb`


## Run
On your iPhone
```bash
ssh 192.168.114.53

# -D is daemon mode, -l to specify a specific host
frida-server -l 0.0.0.0:3039 -D 
```

On your testing host
The following CLI commands use SSH over the network. This is very slow on iPhones. I recommend using iproxy for connection.
```bash
/home/akenofu/.local/bin/frida-ps -ia -H 192.168.114.153:3039

objection -N -h 192.168.114.153 -p 3039 -d --gadget <application_name> explore 

/home/akenofu/.local/bin/objection -N -h 192.168.114.153 -p 3039 -g com.highaltitudehacks.DVIAswiftv2 explore
```

