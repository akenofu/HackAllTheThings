# Frida Setup
## Install
### Download Frida-Server
> To identify the system architecture, and correct friend version to download, use `uname -a` inside the mobile device's SSH terminal.
#### For rootless Jailbreaks, 
Download `frida_16.0.8_iphoneos-arm.deb` from [miticollo.github.io/repos/my/debs/frida at main · miticollo/miticollo.github.io · GitHub](https://github.com/miticollo/miticollo.github.io/tree/main/repos/my/debs/frida), or [Build frida-server binary for rootless Jailbroken devices from scratch](https://gist.github.com/miticollo/6e65b59d83b17bacc00523a0f9d41c11#xcode).

For more on Frida and rootless Jailbreaks, refer to [iOS rootless jailbreak package · Issue #2288 · frida/frida · GitHub](https://github.com/frida/frida/issues/2288).
#### For rooted Jailbreaks:
- Download the binary from [Releases · frida/frida (github.com)](https://github.com/frida/frida/releases)
### Installation 
- Transfer package to mobile with scp
- Inside the iPhone's SSH session, switch to root, and Install the package with `dpkg -i frida_16.0.8_iphoneos-arm.deb`

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
frida-ps -Uai | grep -i <application_name> 

objection -N -d --gadget <application_name> explore 

# attach to process by PID
objection -g 4016 explore
```

