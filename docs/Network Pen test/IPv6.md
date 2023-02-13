# IPv6
## Host discovery
### Windows
```batch
:: Ping
ping <address>

::IPv6 NDP Table
netsh interface ipv6 show neighbors

:: IPv6 Route Table 
netsh interface ipv6 show route
```
### Linux
```bash
# Ping
ping6 <target>

# IPv6 NDP Table
ip -6 neighbor show

# IPv6 Route Table
netstat -A inet6 -rn
```
### macOS
```bash
# Ping
ping6 <target>

# IPv6 NDP Table
ndp -an

# IPv6 Route Table
netstat -f inet6 -rn
```

### nmap
TBD
### msf
TBD