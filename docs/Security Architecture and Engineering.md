# Security Architecture and Engineering
# Key Concepts
### Network Segregation and Segmentation
While network segregation isolates crucial networks from external networks such as the internet, network segmentation splits a larger network in to smaller segments — also called subnets — usually through switches and routers. [^1]

If you have a [flat network](https://insights.sei.cmu.edu/blog/network-segmentation-concepts-and-practices/) (an architecture where all systems connect without going through intermediary devices such as a bridge or router), it is relatively easy for a bad actor to gain access to the entire system through one access point. While flat networks provide fast and reliable connectivity, this lateral access between systems makes them especially vulnerable within today’s modern and complex interconnected organizations. [^2]

**It prevents the client-client pivot: attackers can only pivot against servers**

### Defensible Networks
Defensible Networks have the following characteristics:
- **Monitored**: Deploy IDSes and IPSes
- **Inventoried**: Know every host and application
	- All systems and hosts on the network
	- Where is sensitive data ,e.g., PII stored
	- Where must the data be encrypted?
- **Controlled**: Ingress and egress filtering
- **Claimed**: Identify owners of all systems
- **Minimized**: Reduce the attack surface
- **Assessed**: Conduct vulnerability assessments
- **Current**: Patched

## Zero Trust 
Forrester describes the three concepts of Zero Trust:
- Ensure all resources are accessed securely regardless of location
- Adopt a least privilege strategy and strictly enforce access control
- Inspect and log all traffic

Software Defined Networking and Network Virtualization are key network 
components of Zero Trust.

Micro-Segmentation provides filtering between every interface on every system on a network; This is considered an end-goal of the Zero Trust Model.

## Software Defined Networking (SDN) vs Network Virtualization
Though the term software‐defined networking means different things to different people, this much is clear: SDN allows software to control the network and its physical devices. SDN is all about software talking to hardware — you can essentially call it a next‐generation network management solution. Though it centralizes management and allows you to control network switches and routers through software, SDN doesn’t virtualize all networking functions and components. In other words, SDN doesn’t allow you to run the entire network in software. Hardware remains the driving force for the network. 

In contrast to SDN, network virtualization completely decouples network resources from the underlying hardware… With your networking resources decoupled from the physical infrastructure, you basically don’t have to touch the underlying hardware. Virtual machines can move from one logical domain to another without anyone having to reconfigure the network or wire up domain connections. You implement network virtualization in the hypervisor layer on x86 servers rather than on network switches.

## Station Isolation
Many corporate wireless solutions offer 'station isolation': a client on a wireless access point may speak to the AP (which is also a switch and a router) only. 
- Clients may not access other clients on the same AP 
- Station isolation is also called client isolation 
-  Prevents infections from spreading from guest to guest

## WPA2 Enterprise
PA2 Personal is intended for home or small business use 
- The encryption key is a pre-shared key (PSK) 
WPA2 Enterprise is intended for businesses 
- The encryption key is unique to each client after logging in 
- Uses 802.1X authentication and RADIUS servers which allow: 
	- Active Directory/LDAP authentication 
	- Digital certification authentication 
	- Dynamic VLAN placement 
	- Centralized key management 
	- Fine-grained access control 
	- Server <-> Client validation
Unique encryption keys mean less vulnerable to cracking or snooping Certificate validation helps prevent man-in-the-middle attacks

## Layer 2 Attacks: Switches
- CAM Overflow 
	- The Switch CAM (Content Addressable Memory) maintains a mapping of MAC/Port pairs.
	- Tools such as macof (part of dsniff) can flood a network with randomly generated MAC addresses, potentially filling the CAM table 
	- Once the CAM table is full: some switches will fall back to 'hub mode': sending all frames to all ports
- MAC Spoofing

## Hardening Against Layer 2: Switch Attacks
- Cisco Discovery Protocol (CDP) is a layer 2 plaintext broadcast protocol designed for troubleshooting o It allows Cisco devices to 'see' each other 
- CDP leaks a lot of critical information to every system on the subnet 
- CDP should be disabled unless expressly required

## Port Security
- Port security is a critical feature offered by managed switches (as opposed to unmanaged switches that offer no management interface).
- Port security is primarily focused on controlling the MAC address that is allowed to connect to each port (and also to prevent multiple MACs on one port)

## MAC Limiting and Sticky MAC Addresses
- MAC limiting limits how many MAC addresses may be associated with one port 
- Sticky addresses mean the switch will learn the MAC address of each connected system, and automatically add them to the running configuration

In addition to the options shown above, sites should decide how to handle a violation of the maximum MAC address count. As stated previously: this could be a sign of ARP cache poisoning. It could also indicate that a user has connected a network hub to a switch, or perhaps that a network device is malfunctioning. In all of those cases: the network engineering team or Security Operations Center (SOC) should know.

## Layer 2 Attacks: ARP
- ARP Spoofing remaps an IP address to a new illegitimate MAC address
- ARP cache poisoning tricks a system into caching the spoofed ARP entry

## Hardening Against Layer 2: ARP Attacks
DHCP Snooping
- Configure the switch to trust DHCP responses from specific ports 
- Only allow DHCP responses from these ports 
- Clients will not receive bogus DHCP responses from non-trusted ports 

Dynamic ARP Inspection (DAI)
- DHCP snooping creates a binding database of valid MAC/IP pairs it learns by tracking valid DHCP traffic 
- Dynamic ARP Inspection checks this database before forwarding ARP responses

## Layer 2 Attacks: DHCP 
**DHCP Starvation**
An attacker may attempt to request all available DHCP addresses 
- This is called a DHCP starvation attack, which often leads to a rogue DHCP server attack (discussed next) 
- Most DHCP servers have a fairly small pool of addresses (often less than 255) 
- Once all leases are claimed: the DHCP server will not be able to offer new leases until the old ones expire

**DHCP Rogue Server**
- A rogue DHCP server attack often follows A DHCP starvation attack 
- Once the real DHCP server is out of leases: a rogue server can then serve addresses as well as additional information o Including the default gateway, DNS, etc. 
- This makes launching Man-in-the-Middle attacks quite easy 
- It also allows the rogue server to send clients forged DNS responses, directing clients to malicious sites

## Hardening Against Layer 2: DHCP Attacks
DHCP snooping is a DHCP security feature that provides network security by filtering untrusted DHCP messages and by building and maintaining a DHCP snooping binding database, also referred to as a DHCP snooping binding table… 

DHCP snooping acts like a firewall between untrusted hosts and DHCP servers. You use DHCP snooping to differentiate between untrusted interfaces connected to the end user and trusted interfaces connected to the DHCP server or another switch

## VLAN
A [VLAN](http://www.ipwithease.com/what-is-vlan-virtual-lan/) is a group of switch ports administratively configured to share the same broadcast domain [^3].

## Private VLANs
Private VLANs (PVLANs) are used mainly by service providers. The main purpose of [Private VLAN](http://www.ipwithease.com/concept-of-private-vlan/) ([PVLAN](http://www.ipwithease.com/concept-of-private-vlan/)) is to provide the ability to isolate hosts at [Layer 2](https://networkinterview.com/osi-model-the-7-layers/) instead of Layer 3. By using PVLAN we are splitting that domain into some smaller broadcast domains. In other words we may summarize Private VLAN as **”** **VLANs in VLAN “** [^3]
![](/Screenshots/Pasted%20image%2020230212164002.png)


## Private VLANs (PVLANs)
Types of Private VLAN Ports 
- Promiscuous  
	- Able to send traffic to any device on the VLAN 
	- Normally includes the default gateway 
- Isolated 
	- May only communicate with promiscuous ports 
	- Cannot send traffic to other ports 
- Community 
	- May send traffic to promiscuous ports or other community ports 
	- Cannot send traffic to isolated ports

## Layer 3 Attacks: NTP
**TP Amplification Attacks**
- UDP-based services can sometimes be used for spoofed Denial of Server (DoS) attacks 
- NTP supports a 'monlist' command, which will return the client IP addresses that have synced most recently o Up to 600 addresses can be sent 
- The attacker can then spend a spoofed NTP monlist command to a vulnerable server 
	- In a recent test by Cloudflare1 , one spoofed 234-byte UDP packet resulted in 100 response packets, totaling 48,000 bytes 
	- Resulting in an amplification factor of 206 times

## Bogon Filtering
A packet routed over the public Internet (not including over VPNs or other tunnels) should never have a source address in a bogon range. These are commonly found as the source addresses of DDoS attacks.
- Bogons are network blocks that are not routed on the internet, for example:
	- 0.0.0.0/8
	- 10.0.0.0/8
	- 100.64.0.0/10
	- 127.0.0.0/8
	- 169.254.0.0/16
	- 172.16.0.0/12
	- 192.0.0.0/24
	- 192.0.2.0/24
	- 192.168.0.0/16
	- 198.18.0.0/15
	- 198.51.100.0/24
	- 203.0.113.0/24
	- 224.0.0.0/4
	- 240.0.0.0/4

The external firewall may be used to filter traffic from Bogon network blocks. It's a simpler routing decision since it uses the IP address only, but either routers or firewalls may be used

## Monitor Darknet IPs
A "darknet" originally referred to unused/non-routed IP addresses owned by an organization.

Why monitor Darknets?
- Simple: malware likes to scan
- We recommend setting up a darknet route to those addresses and monitoring the resulting traffic 
	- Watch for explosions in traffic (this can be your fastest IDS)

All traffic sent to a darknet is bogus, by definition:
- There are two types of darknet traffic sources: misconfigured and/or malicious traffic 
- IP darknet monitoring can offer critical insights into misconfigured and/or malicious traffic on a network

**IP Darknet Architechture**
- Route all IP darknet traffic to a dedicated darknet router
	Monitor this traffic via SNMP 
- That router forwards traffic to a 'packet vacuum' sensor 
	- This sensor sniffs and drops the traffic

## IPv6
IPv6 is usually deployed "dual-stack," meaning systems use both IPv4 and 
IPv6 addresses
- RFC 6555 describes the process of deciding which address to use via the 
Happy Eyeballs (HE) algorithm (aka fast fallback):
	- “The proposed approach is simple – if the client system is dual-stack capable, then fire off connection attempts in both IPv4 and IPv6 in parallel, and use (and remember) whichever protocol completes the connection sequence first. The user benefits because there is no wait time and the decision favours speed – whichever protocol performs the connection fastest for that particular end site is the protocol that is used to carry the payload.”1

• In practice: many dual-stack systems will try to resolve both the A (IPv4) 
and AAAA (IPv6) DNS records of a name and then immediately attempt to use the IPv6 address if the AAAA record resolves.

## Types of IPv6 Addresses
Pv6 systems may use three separate address types:
- Link-local addresses
	- Used on the local subnet only, network prefix begins with "fe80"
	- All IPv6-enabled systems have this address
- Unique Local Addresses (ULA)
	- May be used on privately owned networks, network prefix begins with "fd00"
	- They are not routed publicly
	- Some organizations do not use these addresses
- Global Unicast Addresses
	- Routed publicly

Systems may have multiple Unique Local and Global Unicast Addresses

Unique Local Addresses are often skipped by organizations that use IPv6: they simply use Link Local and Global Unicast Addresses. Why use Unique Local Addresses? These addresses cannot (directly) reach the internet, which can add a layer of defense in depth protection (in addition to firewalls, etc.)

## IPv6 Address Format
RFC 4193 describes the Unique Local Address format: 
- Prefix: FC00::/7 prefix to identify Local IPv6 unicast addresses. 
- L: Set to 1 if the prefix is locally assigned. Set to 0 may be defined in the future. 
- Global ID: 40-bit global identifier used to create a globally unique prefix. 
- Subnet ID:16-bit Subnet ID is an identifier of a subnet within the site. 
- Interface ID: 64-bit Interface ID3

Global Unicast Address allocations are issued to organizations by Regional Internet Registries, such as ARIN, RIPE, AFRINIC, APNIC, and LACNIC 

Unique Local Addresses are used locally but are designed to be globally unique This avoids requiring renumbering subnets if two organizations connect Unique Local Address subnets via an extranet connection.

Unique local address Global IDs are generated randomly o 40 bits of the address are set randomly 
- There are 1.1 trillion possible subnets 
- The odds of a collision between two organizations is quite small

## IPv6 Privacy Extension Addresses and Temporary Addresses
IPv6 addresses created via SLAAC expose the MAC address, which 
may result in privacy issues.
- As a result: IPv6 privacy extension addresses are used by most current operating systems
- The privacy extension address is not based on the MAC address (discussed next)
- Most systems use privacy extension addresses for the unique local and global unicast addresses, and continue to embed the MAC address in the link-local address (used on the local subnet only)

Most systems also create two addresses for each unique local and global unicast address
- The temporary address is normally preferred for all communication

This combination adds an additional layer of privacy: these addresses are not tied to the MAC (privacy extensions), *and* they change routinely (temporary addresses)

## ::1 Addresses
- ::1 is the equivalent of the IPv4 address 127.0.0.1 
- fc00::/7 is reserved for unique local addresses 
	- Equivalent to IPv4 RFC1918 addresses (such as 192.168.0.0/16, 10.0.0.0/8, etc.) 
	- Includes fc00::/8 and fd00::/8 o While reserved, usage of fc00::/7 is not yet defined 
	- Sites use fd00::/7 to assign unique local addresses

## IPv6 Multicast Addresses
IPv6 does not support broadcast addresses and uses multicast 
addresses to perform a similar function to IPv4's broadcast 
addresses
- Broadcast addresses are used for one -> all devices on network
- Multicast addresses are used for one -> multiple devices on the network e.g. : routers, multicast DNS, NTP, etc.
- IPv6 uses the ff00::/8 network prefix for multicast addresses

Two important IPv6 multicast addresses (more listed in the notes):
- ff02::1 - All local nodes 
- ff02::2 - All local routers
IPv6 Multicast addresses operate at different scopes:
- ff01:: Interface-Local (loopback)
- ff02:: Link-Local (same LAN)
- ff05:: Site-Local (one location)
- ff08:: Organization-Local (one organization)
- ff0e:: Global scope

The Multicast scope has consequences for IPv6 scanning:
- The most commonly-used multicast addresses are ff02::1 (all local nodes) and 
ff02::2 (all local routers), which are Link-Local in scope
- This limits their scope (and usefulness) for scanning purposes

## Scanning IPv6
While end-to-end scans of IPv6 networks are not effective, the following methods are helpful:
- IPv6 ping to multicast addresses
- Inspecting the IPv6 neighbor discovery protocol (NDP) table
- Inspecting the IPv6 route tables

IPv6 Multicast addresses that begin with "ff02::" operate at the Link-Local (LAN) scope. Scanning local IPv6 systems is easy. Most systems are dual-stack, running both IPv4 and IPv6. This means discovering local systems via traditional methods was already easy: a simple ARP sweep or ping scan will likely discover all systems on a local subnet.

## Scanning IPv6 Limitations
Discovering non-local IPv6 systems is much more challenging. Larger-scope IPv6 multicast addresses are rarely used. End-to-end sweeps of /64 networks are not feasible: ping .1, then .2, then .3… and the Sun will supernova before a sweep of the 18+ quintillion addresses on a /64 subnet will complete.

One method for discovering remote IPv6 systems: rely on dual-stack systems and use IPv4 scans. 

What happens if an organization does *not* run dual-stack, and has some IPv6-only servers? These will be very difficult to discover if they are not on the local subnet and are not discoverable through other traditional 
reconnaissance and scanning methods (such as DNS, Google searches, etc.).


## Preventing and Detecting IPv6 Tunneling
Many forms of IPv6 via IPv4 tunnels carry IPv6 where TCP or UDP would normally be
- The layer 3 header "Protocol" field would be 41 (IPv6) in this case
- Configure Next-Gen Firewalls, IDSes and/or IPSes to block/alert protocol 41, Snort syntax: `ip_proto:41`

## Unauthorized IPv6 Router Advertisements
In this scenario: a black hat compromises an internal client system via a 
phishing attack via IPv4
- The black hat then creates a 6to4 tunnel from the compromised client to the IPv6 
internet
- The compromised client then sends IPv6 router advertisements to the local subnet, 
identifying the client PC as an IPv6 router
- The local systems create a global unicast address, using the network prefix assigned by the rogue IPv6 router

That local subnet is now directly exposed to the public IPv6 internet.

Rogue Advertisement (RA) Guard mitigates this risk, see notes for details. RA Guard also mitigates DoS via IPv6 Route Advertisement flooding.

### DMZ Design
The risk of a compromised DMZ system pivoting into internal systems (or other DMZ systems) must be mitigated 
- Untrusted->DMZ access should be tightly filtered, plus DMZ->trusted 
-  DMZs with multiple servers should be broken up into individual trust zones (or separate DMZs)

Private VLANs may also be used 
- Promiscuous port: the firewall DMZ interface 
- Isolated ports: DMZ servers that only need to send traffic via the firewall 
- Community ports: when multiple DMZ systems need to communicate with each other (and via the firewall)

## Network Segmentation Principles
• Segmentation should facilitate prevention & detection
• Systems and data with different classification levels (tiers) must reside in different zones
• Control points are implemented at ”gates” where all ingress & egress traffic is inspected and access control policies enforced
• Balance security with usability — Higher segmentation adds complexity and administrative burden. Insufficient segmentation can make the network indefensible

## Example of Tiers – Based on Criticality and Business Impact
- Tier 1:  Critical components to maintain operations, including domain controllers, exchange servers, and network infrastructure devices.
- Tier 2: Internal systems containing PII and associated data, including databases, sharepoint servers and other web servers.
- Tier 3: External facing data-providing services
## Router ACLs
- Modern routers provide layer 3/4 firewall capabilities 

- Modern Cisco routers support standard and extended ACLs

	Standard: filters on source only (layer 3)
	Extended: filters on source or destination, as well as based on ICMP types/codes and TCP/UDP ports

• ACLs may be inbound or outbound

	Inbound: applied to packets entering the router
	Outbound: applied to packets before routing a packet to an outbound interface

## Enforcing Segregation
Organizations are often faced with legacy systems that lack vendor support.

All access (including internal) to unsupported systems should be filtered. Options include:
- Host-based firewall
- VLAN ACLs
- Router or Firewall filtering

Another option: Velcro a tiny USB powered firewall to the device

## Proxy Types
**Forward:**:
Systems request access through a proxy to access a resource. Example: Web Proxy

**Reverse:**
Service protected by forcing connections through a proxy. Example: Web Application Firewall / Load Balancer

![](/Screenshots/Pasted%20image%2020230212164259.png)

Inspection of web traffic includes filtering based on:
- Site category
- URLs
- File contents
- Data loss prevention
- MIME Types
- User Agents
- Global reputation
- Status codes
- Cookies
- Form values
- Protocol anomalies
- Certificates
- AV Signatures
- Sandbox analysis

## SSL Interception
Encryption blinds a proxy by default: Interception of traffic would cause errors and break sites. 

SSL Interception allows analysis of encrypted sites
- Requires proxy to act as a trusted certificate authority
- Proxy generates certificates per site accessed

## Proxy Deployment
Proxies are deployed in one of two modes
- Transparent - Traffic goes through proxy regardless of endpoint configuration
- Explicit - Endpoints must be configured to use the proxy

## Proxy Placement
Ideally, everything would go through an explicit proxy
- What about devices that do not support proxies?
- What about devices that enter and leave the network?

Segmentation should be considered for "dumb" devices
- And possibly use a transparent proxy to limit access. Systems supporting proxy need access to the proxy
- Through direct access via internal or VPN access
- Or via proxy in the cloud or internet facing DMZ system

## Securing SMTP

-   [Sender Policy Framework (SPF)](https://support.google.com/a/answer/33786): Specifies the servers and domains that are authorized to send email on behalf of your organization. [^4] 
-   [DomainKeys Identified Mail (DKIM)](https://support.google.com/a/answer/174124): Adds a digital signature to every outgoing message, which lets receiving servers verify the message actually came from your organization. [^4]
-   [Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://support.google.com/a/answer/2466580): Lets you tell receiving servers what to do with outgoing messages from your organization that don’t pass SPF or DKIM [^4]

##  Sender Policy Framework (SPF)

DNS record validates email sent from an authorized source • Based on authorized IP addresses
- Based on DNS domain information (A record, MX record) 
- Can specify no email comes from a specific sub-domain

## DomainKeys Identified Mail (DKIM) 

Uses digital signatures to validate email

- Means asymmetric keys (private + public) and hashing Keys are created for each selector (may just need one)
- Private key goes to email system(s)
- Public key saved in DNS TXT record under `_domainkey.domain.com`

## Domain-Based Message Authentication, Reporting, and Compliance (DMARC)
DMARC verifies domain authentication via SPF or DKIM
-  Can use SPF/DKIM to force alignment of visible From


DMARC policy dictates actions and protection level
- Policy – Monitor, Quarantine, Reject
- Alignment – Strict, Relaxed


## Intentional Email Modification
SMTP proxies and email systems can add to a message
- Disclaimer messages
- Custom headers or footer banners
- "This message came from an external source"
- "This message may be a phishing email acting as an executive"

Requires setting up rules to do X when Y is true
- If display name matches executive add phishing message
- If external source add external source message


# Resources
[Defensible Security Architecture & Engineering: Implementing Zero Trust for the Hybrid Enterprise Course | SANS SEC530](https://www.sans.org/cyber-security-courses/defensible-security-architecture-and-engineering/)

****

[^1]: [Network Segregation: What Is It and Why Is It Important? (parallels.com)](https://www.parallels.com/blogs/ras/network-segregation/#:~:text=The%20Difference%20between%20Network%20Segregation%20and%20Segmentation&text=While%20network%20segregation%20isolates%20crucial,usually%20through%20switches%20and%20routers.)
[^2]: [7 Network Segmentation Best Practices to Level-up | StrongDM](https://www.strongdm.com/blog/network-segmentation)
[^3]: [VLAN vs Private VLAN - IP With Ease](https://ipwithease.com/vlan-vs-private-vlan/)
[^4]: [Help prevent spoofing and spam with DMARC - Google Workspace Admin Help](https://support.google.com/a/answer/2466580?hl=en)