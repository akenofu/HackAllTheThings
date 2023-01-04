## Linux Directories
- `/usr/bin` managed by package manager
- `/usr/local/bin` managed by user

***
## Config Files Default Locations
- Apache config `/etc/apach2/sites-enabled/000-default.conf`
- gitlab rails `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`
- AWS `~/. aws/config`

***

## Share VPN Connection between 2 VMs
On The Linux VM with the openvpn connection
```bash
# Enable IP Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward Connection
iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT

# Add NAT
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o tun0 -j MASQUERADE
```

On The windows vm
```bash
# Add new route
route add 10.10.10.0 mask 255.255.255.0 <router_ip>
```

References:
[Networking VMs for HTB | 0xdf hacks stuff](https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html)
[Ippsec - HTB Sharp](https://youtu.be/lxjAZELJ96Q?t=3321)

***

## Log Incoming connections to file
```bash
# Setup Logging rule
iptables -A INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IP Tables New-Connection: " -i tun0

# Confirm rule was added
iptables -L

# Check Log file for the connections
grep -i iptables /etc/log/messages 
```

***

## Useful terminal tricks
### Pipe to clipboard
```bash
# Install package via npm
npm install -g clipboard-cli

# pipe output to clipboard
echo foo | clipboard 

# Via xsel
ls | xsel -ib

# Via xclip
ls | xclip -sel clip

# Pipe clipboard to file using xclip
xclip -selection clipboard -o > clipboard.txt
```

***


## Capabilities
```bash
# Allow python to bind to privileged ports
sudo setcap  cap_net_bind_service+eip  $(which python3.9)

# Check Capabilities
getcap $(which python3)

# or
stat $(which python3)
```

***

## Debian Packages
```bash
ar x mypackage.deb
```

***

## Grab IP From file system
```bash
cat /proc/net/fib_trie
```

---

## Decompress & Extract

```bash
unzip arc.zip -d arc

tar xvf arc.tar 

gzip -d arc.gz
```

---
## Bash Tricks
```bash
# Pipe stderr to stdout
curl http://doesnotexist.com 2>&1
```