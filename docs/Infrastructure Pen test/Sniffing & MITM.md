# Sniffing
## TCP Dump
```bash
tcpdump -i any -w tcpdump-all-interfaces.pcap
```
## Extract creds from PCAP file
[PCreds](https://github.com/lgandx/PCredz)
[BruteShark](https://github.com/odedshimon/BruteShark)
```bash
# BruteSharkCli
./BruteSharkCli -i ~/bettercap-tcpdump-all-interfaces.pcap -m Credentials,FileExtracting,NetworkMap,DNS,Voip 

# PCreds
```

# MITM
## Layer 2

## ARP Spoofing
### Explanation
[ARP Spoofing - frostbits-security MITM Cheatsheet](https://github.com/frostbits-security/MITM-cheatsheet#arp-spoofing)
[Gratuitous_ARP](https://wiki.wireshark.org/Gratuitous_ARP)

### Tools
[[Bettercap]]
***
## Layer 4
## NetBIOS (LLMNR) spoofing
If a windows client cannot resolve a hostname using DNS, it will use the Link-Local Multicast Name Resolution ([LLMNR](https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10))) protocol to ask neighbouring computers. LLMNR can be used to resolve both IPv4 and IPv6 addresses.

If this fails, NetBios Name Service ([NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)) will be used. NBNS is a similar protocol to LLMNR that serves the same purpose. The main difference between the two is NBNS works over IPv4 only.

The problem of this pretty cool thing is that when LLMNR or NBNS are used to resolve a request, any host on the network who knows the IP of the host being asked about can reply. Even if a host replies to one of these requests with incorrect information, it will still be regarded as legitimate.

The attacker may request NTLM authentication from the victim, which will cause the victim's device to send an NTLM hash, which can then be used for brute force attack.

Also there is a chance to perform WPAD spoofing.

### WAPD Spoofing
WPAD spoofing can be referred to as a special case of LLMNR- and NBNS-spoofing. Web Proxy Auto Discovery protocol is used for automatic configuration of HTTP proxy server.

The device sends an LLMNR/NBNS request with a wpad host, obtains the corresponding IP address and tries to access the wpad.dat file containing information about proxy settings via HTTP.

As a result, an attacker can perform LLMNR/NBNS spoofing and provide the victim with his own wpad.dat file, resulting in all HTTP and HTTPS traffic going through the attacker.

[Quick tutorial to grab clear text credentials](https://www.trustedsec.com/2013/07/wpad-man-in-the-middle-clear-text-passwords/)  
[How Microsoft Windows’s name resolution services work and how they can be abused](https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/)


***
## References
[frostbits-security MITM Cheatsheet](https://github.com/frostbits-security/MITM-cheatsheet)