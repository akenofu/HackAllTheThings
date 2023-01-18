# LLDB
## Setup
1. On your host, Install lldb (Available from Parrot OS' sources)
	```bash
	sudo apt-get install lldb
	```
2. On your phone, download the binaries from [GitHub - wstclzy2010/iOS-debugserver: including iOS10/iOS12/iOS13/iOS14 debugserver](https://github.com/wstclzy2010/iOS-debugserver). The binaries from the previous repo are signed with the correct entitlements.
	```bash
	git clone https://github.com/wstclzy2010/iOS-debugserver
	```
3. Copy debugserver to /usr/bin
	```bash
	cp iOS-debugserver/iOS14-debugserver_arm64 /usr/bin/debugserver
	```

	> The debugserver binary needs to be in the /usr/bin directory; otherwise, it will crash on launch.

## Start

> ✔️ Remote Debugging over wifi is very slow, utilize iproxy to debug over USB connection.

1. On your host, configure iproxy
	```bash
	sudo iproxy 1234 1234
	```
2. Inside your iPhone SSH session
	```bash
	# ✅ Recommended Way 
	# launch server with no process attached
	process connect connect://127.0.0.1:1234
	
	# or Wait for process to spawn
	debugserver 0.0.0.0:1234 --waitfor=DVIA-v2
	
	# or attach to running process
	debugserver 0.0.0.0:1234 -a DVIA-v2
	```
3. From your host, inside lldb
	```bash
	lldb
	
	platform select remote-ios
	
	process connect connect://127.0.0.1:1234
	
	# if launched with no process attached
	process attach --pid 5039
	```

## Cheatsheet
```bash
# Show memory map
image dump sections DVIA-v2

# Show disassembly at source address
# Src + offset
dis -s 0x00000001001bd300+0x4138000

# Set breakpoint
br set -a 0x1042f5314

# Show registers
register read

# Write to register
register write x0 0x1

# Break at function call
b ptrace
```