# Pivot & Tunnel
## Cheatsheet
To use sshuttle with JumpHost make sure the `~/.ssh/config` is configured correctly. Checkout [[SSH (22)#Config File Sample for jumphost]]
```bash
# sshuttle
sudo sshuttle --dns -v -r ubuntu 10.1.4.0/24 
```
## Tools

[sshuttle/sshuttle: Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling. (github.com)](https://github.com/sshuttle/sshuttle)

[jpillora/chisel: A fast TCP/UDP tunnel over HTTP (github.com)](https://github.com/jpillora/chisel)