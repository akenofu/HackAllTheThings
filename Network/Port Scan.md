## Namp
```bash
# ipv6 port scan
nmap -6 10.10.10.215

# Host Discovery
nmap -sP 10.10.10.215

# Nmap Via Proxy Chains, Special flags
# Maybe enable quiet mode 
sudo nmap proxychains -sT -Pn -n  -v 10.10.10.13

```

## Manual Firewall Enumeration
- Run wireshark to view traffic
- use `ncat` to connect to port
- Check if firewall is `REJECT`ing the packet or the port is just not listening
- Connect again to a non listening port 
- Compare the response in both cases to identify if the firewall is dropping the request or if the port is not listening.
