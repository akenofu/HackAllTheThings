# SSH
## Identify Authentication methods
```bash
ssh -o PreferredAuthentications=none 102.128.100.51 -p 9001
ssh -o PreferredAuthentications=password 102.128.21.13 -vvv
```

## Identify Server Version and banner
```bash
# Find Debug1 Version
ssh -v 10.10.10.14
```

## Identify Supported Crypto Cyphers
```bash
# Ciphers
ssh 10.10.14.2 -Q cipher

# Kex Algorithms
ssh 10.10.14.2 -Q kex
```

## Username enumeration
Metasploit `use scanner/ssh/ssh_enumusers`

## Brute Force
Metasploit `use scanner/ssh/ssh_login`

## SSH Malicious Strings
Metasploit `use auxiliary/fuzzers/ssh/ssh_version_2`

## File Transfer
- Copy files over SSH
	```bash
	scp -i C:\temp\op6 C:\AndroidTools\tmp\AlwaysTrustUserCerts.zip root@192.168.1.17:/sdcard
	
	# Copy Local File to Remote System
	scp file.txt remote_username@10.10.0.2:/remote/directory
	
	# Copy File from remote system to localhost
	scp -r "remote_host:/remote/directory/*.out" /remote/directory
	
	```
	
	
## Port Forwarding
- Local Port  Fwd (localhost:80 -> SuperServer:80)
	```bash
	ssh -L 80:localhost:80 SUPERSERVER
	```
- Reverse Port Fwd (tinyserver:80 -> localhost:80)
	```bash
	ssh -R 80:localhost:80 tinyserver
	``` 


## Non-interactive log on
```bash
sshpass -p P@ssw0rd ssh -o PubkeyAuthentication=no sonny@10.10.10.152
```

## Jumphost
```bash
TODO
```

## Config File Sample for jumphost
### Using ProxyJump
```vim
Host bastion-host
        Hostname 10.1.2.7
        User akenofu
        Port 5050
        IdentityFile /home/akenofu/bastion.pem
Host ubuntu
        Hostname 10.1.8.7
        User akenofu
		ProxyJump bastion-host
```

### Using ProxyCommand
```vim
Host bastion-host
        Hostname 10.1.2.7
        User akenofu
        Port 5050
        IdentityFile /home/akenofu/bastion.pem
Host ubuntu
        Hostname 10.1.8.7
        User akenofu
        ProxyCommand ssh bastion-host -W %h:%p
```

## Scanners
[ssh-audit](https://github.com/jtesta/ssh-audit#ssh-audit)
[rbsec/sslscan: sslscan tests SSL/TLS enabled services to discover supported cipher suites (github.com)](https://github.com/rbsec/sslscan)