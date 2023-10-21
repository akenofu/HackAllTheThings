# Port Scan
## Namp
```bash
# ipv6 port scan
nmap -6 10.10.10.215

# Host Discovery
nmap -sP 10.10.10.215

# Nmap Via Proxy Chains, Special flags
# Maybe enable quiet mode 
sudo nmap proxychains -sT -Pn -n  -v 10.10.10.13

# UDP Top 1000 port scan
nmap -v -oN bastion-top-1000-udp.out -Pn -sU -T5 10.10.10.13

# Quick and sneaky
nmap -p- -v -oN 10.1.6.5-all-tcp.out -Pn -sT -T5 10.1.6.5
```

## Manual Ping sweep
```bash
for i in $(seq 1 254) ;do (ping -c 1 172.27.8.${i} | grep "bytes from" &) ;done
```

## Manual Firewall Enumeration
- Run wireshark to view traffic
- use `ncat` to connect to port
- Check if firewall is `REJECT`ing the packet or the port is just not listening
- Connect again to a non listening port 
- Compare the response in both cases to identify if the firewall is dropping the request or if the port is not listening.

## For segmentation testing checkout [[Segmentation Testing#Segmentation penetration testing]]