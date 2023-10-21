# Segmentation Testing

## Introduction
Network segments are now a part of any organization or business’s infrastructure. Network segmentation is the splitting of a computer network within the infrastructure according to business requirements.

Segmentation of a network serves many purposes. It helps in avoiding congestion in the overall network and isolates crucial segments (those that have critical data) from other segments. Every organization follows their own segmentation process and procedures depending upon their business requirements.

## Terms that you need to be aware of

There are various terms which might confuse us and need to be understood before performing segmentation penetration testing.

**CDE in-scope**: VLANs which fall under CDE in-scope are the VLANs which store, hold, process and transmit cardholder data. It should be truly isolated from the external world and should have a high level of security on each host that falls under CDE in-scope.

**Non-CDE in-scope**: VLANs which fall under non-CDE in-scope are the VLANs which do not store, hold, process and transmit cardholder data but having dependencies from CDE in-scope. As we already know that CDE in-scope has the limitation of being not exposed to the external world, non-CDE in-scope provides exclusive services and external resources to CDE in-scope. CDE in-scope has certain dependencies which need to be fulfilled by non-CDE in-scope. For instance, patch servers (from non-CDE in-scope) provide patches and update to CDE in-scope hosts. The antivirus server provides antivirus solutions to CDE in-scope. It truly depends on infrastructure-to-infrastructure and business requirements.

**Non-CDE out-of-scope**: VLANs which fall under non-CDE out-of-scope are the VLANs which do not store, hold, process and transmit cardholder data and or have any kind of dependencies from CDE in-scope. They should not be allowed to communicate with CDE in-scope in any case.

![Pasted image 20210714150824.png](/Screenshots/Pasted%20image%2020210714150824.png)

### Example
![Pasted image 20210714152052.png](/Screenshots/Pasted%20image%2020210714152052.png)

## Segmentation penetration testing
Generally, each host in a PCI in-scope segment and all 65535 ports (for TCP and UDP) should be scanned from PCI out-of-scope. It is always considered best practice to initiate the scan in batches, as it is efficient, and we get results more frequently. We should perform the scan from PCI in-scope to PCI out-of-scope and vice versa.

```bash
# Grab IP from cmd
ip=`ip a s | grep eth0 | grep inet  | grep -oP '[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]' | cut -d "/" -f 1` ; echo $ip
```

```bash
# My go-to all ports tcp scan
sudo ./nmap -p- -n -v -oN control_10.1.1.2-to-pci_10.1.4.0.nmap -Pn -T4 10.1.4.0/25 --min-rate 10000

# Nmap All ports
sudo ./nmap -p- -n -v -oN control_10.1.1.2-to-pci_10.1.4.0.nmap -Pn -T4 10.1.4.0/24

# All ports UDP
sudo nmap -sU -sV -T4 -v -n -Pn –top-ports 10000 -oN udpbatch1intoout.txt -oN udpbatch1intoout.out 10.10.10.1-50
```

```bash
sudo ./masscan 10.1.4.0/25 --rate 100000 -p 0-65535 --banners -oL $ip-to-pci_10.1.4.0.massscan
```

### Open|Filtered Ports
![Pasted image 20210714150123.png](/Screenshots/Pasted%20image%2020210714150123.png)

If you encounter an `open|filtered` port. Use netcat to connect to the port
`nc 10.130.31.24 3130`

> Checkout [[Infrastructure Pen test/Port Scan#Manual Firewall Enumeration]] for more how to manually enumerate the firewall using wireshark and netcat.

## Deciding out-of scope
Remember that improper scoping (deciding something is out of scope without proper verification) can put a business at risk. To be effective, scoping and segmentation require careful planning, design, implementation, and monitoring. Many compromises have occurred via systems and networks incorrectly determined to be out of scope, where the breached entity placed false reliance on segmentation, only to find out after the breach that those controls were not effectively protecting its networks. It is therefore critical that entities focus on the security of their entire environment rather than solely on what is required by PCI DSS in order to minimize the risks to their organizations

## References
[Segmentation penetration testing for PCI compliance - Infosec Resources (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/segmentation-penetration-testing-for-pci-compliance/)

[Guidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf (pcisecuritystandards.org)](https://www.pcisecuritystandards.org/documents/Guidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)