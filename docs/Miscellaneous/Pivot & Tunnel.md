# Pivot & Tunnel

## Host -> EC 2 Instance -> VDI -> Target Domain

### Socks 5
1. Start Chisel on the EC2 instance in server mode
```bash
sudo ./chisel_1.7.7_linux_amd64 server -p 8000 --reverse --socks5
```
2. Start chisel in client mode in the VDI machine
```bash
./chisel_1.7.7_linux_amd64  client <ec2_instance_ip>:8000 'R:socks'
```
3. Port forward local port 9001 on your host to port 1080 on the EC2 instance
	>host : 9001 --> ec2 : 1080  

N.B. I am not sure if administrator privelleges are required.
```bash
ssh -L 9001:127.0.0.1:1080 admin@<ec2_ip> -N
```
4. Configure burp suite to use a socks proxy on your host
![](/Screenshots/Pasted%20image%2020221116095454.png)


### Port forwarding

1. Install SSH Client on the VDI windows machine **with the required capabilities**.

```powershell
Get-WindowsCapability -name openssh.client* -online | Add-WindowsCapability –Online
```

2. Permit low privelleged users to bind to lower range ports (1-1024) **on the EC2 instance**. The admin user which is not root on the ec2 instance won't have the permission to bind to port 443 when remote port forwarding later on in this tutorial.
```bash
sudo sysctl net.ipv4.ip_unprivileged_port_start=443
```

3. Modify the `/etc/sshd/sshd_config` on the **EC2 instance** to keep connections alive regardless of how inactive they are. uncomment the following in the sshd_config file.

```vim
# TCPKeepAlive yes
```

3. Add host file entries that map the target domain to 127.0.0.1 to:
	1. EC 2 Instance host file
	2. Host hosts file

Example host file

```vim
127.0.0.1 localhost
127.0.0.1 <target_domain>
```

4. Set up a remote port forward to port 443 on the EC 2 instance from the VDI machine
> ec2 :443 --> target:443

```powershell
ssh -R 443:<target_domain> admin@<ec2_ip>
```

5. Set up a Local port forward from the host to the ec2 instance
> host : 443 --> ec2 : 443  

```powershell
ssh -L 443:127.0.0.1:443 admin@<ec2_ip>
```

### NAT to NAT
**TBD**, I have not tested this yet. 
#### Wireguard
[NAT-to-NAT VPN with WireGuard](https://staaldraad.github.io/2017/04/17/nat-to-nat-with-wireguard/)
#### Tailscale
Tailscale is [a modern VPN](https://tailscale.com/) built on top of [Wireguard](https://www.wireguard.com/). It [works like an overlay network](https://tailscale.com/blog/how-tailscale-works/) between the computers of your networks - using [NAT traversal](https://tailscale.com/blog/how-nat-traversal-works/).

Everything in Tailscale is Open Source, except the GUI clients for proprietary OS (Windows and macOS/iOS), and the control server.

The control server works as an exchange point of Wireguard public keys for the nodes in the Tailscale network. It assigns the IP addresses of the clients, creates the boundaries between each user, enables sharing machines between users, and exposes the advertised routes of your nodes.

A [Tailscale network (tailnet)](https://tailscale.com/kb/1136/tailnet/) is private network which Tailscale assigns to a user in terms of private users or an organisation.
![](/Screenshots/Pasted%20image%2020221121022359.png)
#### Headscale
`headscale` aims to implement a self-hosted, open source alternative to the Tailscale control server. `headscale` has a narrower scope and an instance of `headscale` implements a _single_ Tailnet, which is typically what a single organisation, or home/personal setup would use.

`headscale` uses terms that maps to Tailscale's control server, consult the [glossary](https://github.com/juanfont/headscale/blob/main/docs/glossary.md) for explainations.

### References
[Allow non-root process to bind to port 80 and 443?](https://superuser.com/questions/710253/allow-non-root-process-to-bind-to-port-80-and-443)
[Windows - Port forwarding using SSH](https://techexpert.tips/windows/windows-port-forwarding-using-ssh/)
[How to use Windows 10/11 SOCKS5 Proxy Settings](https://windowsreport.com/windows-10-socks5-proxy-settings/)
[SSH Socks and Burp](https://blog.malteksolutions.com/ssh-socks-and-burp/)

---
# SShuttle
To use sshuttle with JumpHost make sure the `~/.ssh/config` is configured correctly. Checkout [[Infrastructure Pen test/SSH (22)#Config File Sample for jumphost]]
```bash
# sshuttle
sudo sshuttle -v -r ubuntu 10.1.4.0/24 
```

---
# Misc
## General-purpose bash snippets
```bash
# Kill process listenting on port 443
kill -9 $(sudo netstat -alpn | grep 443 | grep LISTEN | grep -v tcp6 | grep -oP '[0-9]{4,}')
```
