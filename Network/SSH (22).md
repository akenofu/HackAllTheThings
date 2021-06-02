## File Transfer
- Copy files over SSH
	```bash
	scp -i C:\temp\op6 C:\AndroidTools\tmp\AlwaysTrustUserCerts.zip root@192.168.1.17:/sdcard
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
