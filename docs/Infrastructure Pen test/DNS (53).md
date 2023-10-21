# DNS

### Trying leaking hostnames by reverse DNS lookup

```bash
# via nslookup
nslookup
> server 10.10.10.153
> 127.0.0.1
> 10.10.10.153

# Resolve IPs for a DNS name
dig +short <name>

# Using dnsrecon
dnsrecon -r 10.10.10.0/24 -n 10.10.10.204 -d notexistdomain
```


### Zone Transfer
```bash
dig axfr Realcorp.htb @10.10.10.224
```


### Brute Force DNS A records
```bash
gobuster -d dns realcorp.htb -r 10.10.10.224 -w /opt/secLists
```

