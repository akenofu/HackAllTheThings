# Security Architecture
## Purpose

-   Meet [Security and Compliance requirements](https://about.gitlab.com/handbook/security/architecture/#security-architecture-requirements)
-   Ensure best practices are used
-   Ensure [Security Architecture Principles](https://about.gitlab.com/handbook/security/architecture/#security-architecture-principles) are followed
-   Ensure identified security threats are mitigated
-   Bring Risk management early in our processes (design, implementation, management)
-   Provide recommendations to minimize damage when a component is compromised
---
## When to conduct a Security Architecture review?

The review process is integrated into the broader [Architecture workflow](https://about.gitlab.com/handbook/engineering/architecture/workflow/), but can be triggered for:

-   New large projects and initiatives
-   New large features
-   New significant services
-   Cross teams/stage technical changes
---
## Security Architecture Principles (infrastructure and applications)

From: 

- [Security Principles | GitLab](https://about.gitlab.com/handbook/security/architecture/#security-architecture-reviews)
- [OWASP-Principles of Security Engineering.md at master · OWASP/DevGuide (github.com)](https://github.com/OWASP/DevGuide/blob/master/02-Design/01-Principles%20of%20Security%20Engineering.md)

**Assign the least privilege possible**
A security principle in which a person or process is given only the minimum level of access rights (privileges) that is necessary for that person or process to complete an assigned operation. This right must be given only for a minimum amount of time that is necessary to complete the operation.

-   Give only the minimum level of access rights (privileges) that is necessary to a user or service to complete an assigned operation. This right must be given only for a minimum amount of time that is necessary to complete the operation.
-   Do not use administrative accounts for application access
-   Use separate accounts for sensitive data

**Separate Responsibility**
Also known as the compartmentalization principle, or separation of privilege, separation of duties is a security principle which states that the successful completion of a single task is dependent upon two or more conditions that are insufficient for completing the task by itself.

-   Compartmentalize responsibilities and privileges
-   Separation of duties: the successful completion of a single task is dependent upon two or more conditions
-   Don't store secrets along with other non-sensitive data (like settings), even if secrets are filtered out

**Trust cautiously**
Also known as the compartmentalization principle, or separation of privilege, separation of duties is a security principle which states that the successful completion of a single task is dependent upon two or more conditions that are insufficient for completing the task by itself.

-   Assume unknown entities are untrusted
-   Have a clear process to establish trust
-   Validate who or what is connecting
-   Always use a kind of authentication (certificate, password, …)
-   Network controls
-   Do not dynamically load 3rd party code

**Simplest solution possible**
Keep it Simple, Stupid

-   Avoid complex failure modes, implicit behaviours, unnecessary features
-   Use well-known, tested, and proven components
-   Avoid over-engineering and strive for [MVCs](https://about.gitlab.com/handbook/product/product-principles/#the-minimal-viable-change-mvc) instead

**Complete Mediation**
A security principle that ensures that authority is not circumvented in subsequent requests of an object by a subject, by checking for authorization (rights and privileges) upon every request for the object.

In other words, the access requests by a subject for an object are completely mediated every time.

**Audit Sensitive Events**

-   Record all security significant events in a tamper-resistant store
-   Provide notifications for all sensitive events

**Fail securely & use secure defaults**
A security principle that aims to maintain confidentiality, integrity and availability by defaulting to a secure state, rapidly recovering software resiliency upon design or implementation failure. In the context of software security, fail secure is commonly used interchangeably with fail safe, which comes from physical security terminology.

-  Force changes to security sensitive parameters
-   Think through failures - to be secure but recoverable
-   Unless a subject is given explicit access to an object, it should be denied access to that object, aka Fail Safe Defaults

**Never rely upon obscurity**
“The security of a mechanism should not depend on the secrecy of its design or implementation.”

If the details of the mechanism leaks then it is a catastrophic failure for all the users at once.

If the secrets are abstracted from the mechanism, e.g. inside a key, then leakage of a key affects only one user

- Assume attacker with perfect knowledge

**Psychological acceptability**
A security principle that aims at maximizing the usage and adoption of the security functionality in the software by ensuring that the security functionality is easy to use and at the same time transparent to the user. Ease of use and transparency are essential requirements for this security principle to be effective.

Security mechanisms should not make the resource more difficult to access than if the security mechanism were not present.

Problem: Users looks for ways to defeat the mechanisms and “prop the doors open”.


**Implement Defense in depth**

-   Don't rely on a single point/layer of security: Secure every level & Stop failures at one level propagating
-   Encrypt data at rest and in transit
-   Use vulnerability scanners

**Never invent security technology**
This is a security principle that focuses on ensuring that the attack surface is not increased and no new vulnerabilities are introduced by promoting the reuse of existing software components, code and functionality.

-   [Do not roll your own crypto](https://about.gitlab.com/handbook/security/threat-management/vulnerability-management/encryption-policy.html#rolling-your-own-crypto)
-   Use well-known and proven components
-   In doubt, always involve the right SMEs

**Find the weakest link**

-   [Threat model](https://about.gitlab.com/handbook/security/threat_modeling/) the system, repeat, iterate.
-   Identify central components that

    -   share more privileges than the others
    -   have more connections to other components
    -   are entrypoints (login modules, APIs, …)

-   Run [Dependency Scanning](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/)
-   Avoid weak ciphers and algorithms
-   Sometimes consider the humans (users) as the weakest link. Phishing is still widely used for a good reason


****
## Infrastructure security architechure

### Identity, Authentication, and Authorization
Before following along, check out [GitLab Data Classification Standard | GitLab](https://about.gitlab.com/handbook/security/data-classification-standard.html) to understand how gitlab classifies data.

#### Accounts and Credentials

1.  Shared user accounts MUST NOT be used.
2.  Multi-factor (MFA) authentication MUST be enabled for all user accounts.
3.  Access to service account credentials MUST follow the access control of the resources to which the credentials grant access.
4.  Service account credentials MUST be rotated every 365 days.
5.  Non-MFA user account credentials (for example, API keys) MUST be rotated every 90 days.

#### Identity

1.  An identity provider MUST be used for all external accounts.

#### Authentication

1.  Service accounts MAY be authenticated using static credentials, such as API tokens or shared private keys.

#### Authorization

1.  User access to sensitive data MUST be granted through security groups.
2.  Individual access for disaster recovery MAY be granted to system owners as specified in the [tech stack tracking file](https://gitlab.com/gitlab-com/www-gitlab-com/-/blob/master/data/tech_stack.yml).

#### Service Account usage

1.  Service accounts names SHOULD be meaningful.
2.  Service accounts with access to RED data MUST follow the [Access Request](https://about.gitlab.com/handbook/business-technology/team-member-enablement/onboarding-access-requests/access-requests/#shared-account-access-request) process.
3.  Service accounts with access to RED data MUST be limited to single logical scope; for example, a single GCP project.

### Network Security

1.  All network firewalls MUST be configured such that the default policy is DENY.
2.  Network firewall rules SHOULD deny egress by default.
3.  All external communication MUST be encrypted in transit using up to date protocals and ciphers.
4.  All internal communication SHOULD be encrypted in transit if possible.

### Data Handling and Isolation

1.  Data [retention policies](https://about.gitlab.com/handbook/security/records-retention-deletion.html) MUST be followed.
2.  Data MUST be encrypted at rest.
    1.  Data MAY be encrypted using provider managed keys.
3.  Data of different types MUST be logically seperated at rest.
4.  Virtual networks (for example, VPC in GCP) MAY be used as a mechanism for data and workload isolation.

Examples of different data types:

-   User content, such as repository contents or attachments
-   Production derived data, such as logs
-   DFIR (Digital Forensics and Incident Reponse) artifacts, such as system logs and disk images

### Vulnerability and Patch Management

1.  Resources MUST be covered by the [Security Vulnerability Management](https://about.gitlab.com/handbook/security/threat-management/vulnerability-management/) process.

### Change Management and Tracking

1.  Changes to systems that process RED data MUST be tracked in a corresponding issue, merge request, or other reviewable process.

### Audit Logging

1.  Environment audit logs MUST be enabled and stored in accordance with [retention policies](https://about.gitlab.com/handbook/security/records-retention-deletion.html).
2.  Application audit logs, if supported and available, MUST be enabled and stored in accordance with [retention policies](https://about.gitlab.com/handbook/security/records-retention-deletion.html).
3.  Logs MUST be forwarded and processed in a centralized location that provides access to any operational team, such as Security Operations.

---

## Data Classification Standards:

From: [GitLab Data Classification Standard | GitLab](https://about.gitlab.com/handbook/security/data-classification-standard.html)

#### Credentials and access tokens are classified at the same level as the data they protect:

Credentials such as passwords, personal access tokens, encryption keys, and session cookies derive their importance from the data they protect.

#### Combinations of data types may result in a higher system classification level

If there is more than one data type residing in a system, the system should be classified at the highest data classification level of the data being stored, transmitted or processed on that system.

#### Labeling

There is currently no internal requirement to label data according to this standard, however labels are encouraged. By labeling data according to classification level, individuals can quickly refer to this policy for proper handing. Issues that are confidential must be marked accordingly per our [Communication Handbook Page](https://about.gitlab.com/handbook/communication/). It is up to the data owner to ensure that security and privacy settings are applied as per their own requirements.

---

## Key Technical Concepts
### Network Segregation and Segmentation
Network segmentation involves partitioning a network into smaller networks; while network segregation involves developing and enforcing a ruleset for controlling the communications between specific hosts and services. [^1]

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

### Zero Trust 
Forrester describes the three concepts of Zero Trust:
- Ensure all resources are accessed securely regardless of location
- Adopt a least privilege strategy and strictly enforce access control
- Inspect and log all traffic

Software Defined Networking and Network Virtualization are key network 
components of Zero Trust.

Micro-Segmentation provides filtering between every interface on every system on a network; This is considered an end-goal of the Zero Trust Model.

### Software Defined Networking (SDN) vs Network Virtualization
Though the term software‐defined networking means different things to different people, this much is clear: SDN allows software to control the network and its physical devices. SDN is all about software talking to hardware — you can essentially call it a next‐generation network management solution. Though it centralizes management and allows you to control network switches and routers through software, SDN doesn’t virtualize all networking functions and components. In other words, SDN doesn’t allow you to run the entire network in software. Hardware remains the driving force for the network. 

In contrast to SDN, network virtualization completely decouples network resources from the underlying hardware… With your networking resources decoupled from the physical infrastructure, you basically don’t have to touch the underlying hardware. Virtual machines can move from one logical domain to another without anyone having to reconfigure the network or wire up domain connections. You implement network virtualization in the hypervisor layer on x86 servers rather than on network switches.

### Station Isolation
Many corporate wireless solutions offer 'station isolation': a client on a wireless access point may speak to the AP (which is also a switch and a router) only. 
- Clients may not access other clients on the same AP 
- Station isolation is also called client isolation 
-  Prevents infections from spreading from guest to guest

### WPA2 Enterprise
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

### Layer 2 Attacks: Switches
- CAM Overflow 

	- The Switch CAM (Content Addressable Memory) maintains a mapping of MAC/Port pairs.
	- Tools such as macof (part of dsniff) can flood a network with randomly generated MAC addresses, potentially filling the CAM table 
	- Once the CAM table is full: some switches will fall back to 'hub mode': sending all frames to all ports

- MAC Spoofing

### Hardening Against Layer 2: Switch Attacks
- Cisco Discovery Protocol (CDP) is a layer 2 plaintext broadcast protocol designed for troubleshooting o It allows Cisco devices to 'see' each other 
- CDP leaks a lot of critical information to every system on the subnet 
- CDP should be disabled unless expressly required

### Port Security
- Port security is a critical feature offered by managed switches (as opposed to unmanaged switches that offer no management interface).
- Port security is primarily focused on controlling the MAC address that is allowed to connect to each port (and also to prevent multiple MACs on one port)

### MAC Limiting and Sticky MAC Addresses
- MAC limiting limits how many MAC addresses may be associated with one port 
- Sticky addresses mean the switch will learn the MAC address of each connected system, and automatically add them to the running configuration

In addition to the options shown above, sites should decide how to handle a violation of the maximum MAC address count. As stated previously: this could be a sign of ARP cache poisoning. It could also indicate that a user has connected a network hub to a switch, or perhaps that a network device is malfunctioning. In all of those cases: the network engineering team or Security Operations Center (SOC) should know.

### Layer 2 Attacks: ARP
- ARP Spoofing remaps an IP address to a new illegitimate MAC address
- ARP cache poisoning tricks a system into caching the spoofed ARP entry

### Hardening Against Layer 2: ARP Attacks
DHCP Snooping

- Configure the switch to trust DHCP responses from specific ports 
- Only allow DHCP responses from these ports 
- Clients will not receive bogus DHCP responses from non-trusted ports 

Dynamic ARP Inspection (DAI)

- DHCP snooping creates a binding database of valid MAC/IP pairs it learns by tracking valid DHCP traffic 
- Dynamic ARP Inspection checks this database before forwarding ARP responses

### Layer 2 Attacks: DHCP 
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

### Hardening Against Layer 2: DHCP Attacks
DHCP snooping is a DHCP security feature that provides network security by filtering untrusted DHCP messages and by building and maintaining a DHCP snooping binding database, also referred to as a DHCP snooping binding table… 

DHCP snooping acts like a firewall between untrusted hosts and DHCP servers. You use DHCP snooping to differentiate between untrusted interfaces connected to the end user and trusted interfaces connected to the DHCP server or another switch

### VLAN
Resource on VLANs and subnetting:

- [(46) VLANs Explained | Cisco CCNA 200-301 - YouTube](https://www.youtube.com/watch?v=A9lMH0ye1HU)
- [Subnetting != Segmentation | LMG Security](https://www.lmgsecurity.com/pentest-subnetting-segmentation/)


A [VLAN](http://www.ipwithease.com/what-is-vlan-virtual-lan/) is a group of switch ports administratively configured to share the same broadcast domain [^3].

### Zones vs. VLANs
This is Zone Based Firewalling. There are no hard and fast rules as to how you relate your zones to your VLANs but you might for example have 4 VLANs: HR, Finance, Manufacturing and Marketing.

You could then create a Zone for each VLAN, allowing complete firewall control between each of those VLANs (subnets).

However, you might have two zones (which are on two separate /24s) that need to communicate to each other but have no use for firewalling (i.e. there doesn't need to be any security restrictions between these VLANs). In that instance you could have both those VLANs in a single zone which therefore won't be firewalled.

### Private VLANs
Private VLANs (PVLANs) are used mainly by service providers. The main purpose of [Private VLAN](http://www.ipwithease.com/concept-of-private-vlan/) ([PVLAN](http://www.ipwithease.com/concept-of-private-vlan/)) is to provide the ability to isolate hosts at [Layer 2](https://networkinterview.com/osi-model-the-7-layers/) instead of Layer 3. By using PVLAN we are splitting that domain into some smaller broadcast domains. In other words we may summarize Private VLAN as **”** **VLANs in VLAN “** [^3]
![](/Screenshots/Pasted%20image%2020230212164002.png)


### Private VLANs (PVLANs)
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

### Layer 3 Attacks: NTP
**TP Amplification Attacks**

- UDP-based services can sometimes be used for spoofed Denial of Server (DoS) attacks 
- NTP supports a 'monlist' command, which will return the client IP addresses that have synced most recently o Up to 600 addresses can be sent 
- The attacker can then spend a spoofed NTP monlist command to a vulnerable server 

	- In a recent test by Cloudflare1 , one spoofed 234-byte UDP packet resulted in 100 response packets, totaling 48,000 bytes 
	- Resulting in an amplification factor of 206 times

### Bogon Filtering
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

### Monitor Darknet IPs
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

### IPv6
IPv6 is usually deployed "dual-stack," meaning systems use both IPv4 and 
IPv6 addresses
- RFC 6555 describes the process of deciding which address to use via the 
Happy Eyeballs (HE) algorithm (aka fast fallback):

	 “The proposed approach is simple – if the client system is dual-stack capable, then fire off connection attempts in both IPv4 and IPv6 in parallel, and use (and remember) whichever protocol completes the connection sequence first. The user benefits because there is no wait time and the decision favours speed – whichever protocol performs the connection fastest for that particular end site is the protocol that is used to carry the payload.”1

• In practice: many dual-stack systems will try to resolve both the A (IPv4) 
and AAAA (IPv6) DNS records of a name and then immediately attempt to use the IPv6 address if the AAAA record resolves.

### Types of IPv6 Addresses
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

### IPv6 Address Format
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

### IPv6 Privacy Extension Addresses and Temporary Addresses
IPv6 addresses created via SLAAC expose the MAC address, which 
may result in privacy issues.

- As a result: IPv6 privacy extension addresses are used by most current operating systems
- The privacy extension address is not based on the MAC address (discussed next)
- Most systems use privacy extension addresses for the unique local and global unicast addresses, and continue to embed the MAC address in the link-local address (used on the local subnet only)

Most systems also create two addresses for each unique local and global unicast address

- The temporary address is normally preferred for all communication

This combination adds an additional layer of privacy: these addresses are not tied to the MAC (privacy extensions), *and* they change routinely (temporary addresses)

### ::1 Addresses
- ::1 is the equivalent of the IPv4 address 127.0.0.1 
- fc00::/7 is reserved for unique local addresses 

	- Equivalent to IPv4 RFC1918 addresses (such as 192.168.0.0/16, 10.0.0.0/8, etc.) 
	- Includes fc00::/8 and fd00::/8 o While reserved, usage of fc00::/7 is not yet defined 
	- Sites use fd00::/7 to assign unique local addresses

### IPv6 Multicast Addresses
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

### Scanning IPv6
While end-to-end scans of IPv6 networks are not effective, the following methods are helpful:

- IPv6 ping to multicast addresses
- Inspecting the IPv6 neighbor discovery protocol (NDP) table
- Inspecting the IPv6 route tables

IPv6 Multicast addresses that begin with "ff02::" operate at the Link-Local (LAN) scope. Scanning local IPv6 systems is easy. Most systems are dual-stack, running both IPv4 and IPv6. This means discovering local systems via traditional methods was already easy: a simple ARP sweep or ping scan will likely discover all systems on a local subnet.

### Scanning IPv6 Limitations
Discovering non-local IPv6 systems is much more challenging. Larger-scope IPv6 multicast addresses are rarely used. End-to-end sweeps of /64 networks are not feasible: ping .1, then .2, then .3… and the Sun will supernova before a sweep of the 18+ quintillion addresses on a /64 subnet will complete.

One method for discovering remote IPv6 systems: rely on dual-stack systems and use IPv4 scans. 

What happens if an organization does *not* run dual-stack, and has some IPv6-only servers? These will be very difficult to discover if they are not on the local subnet and are not discoverable through other traditional 
reconnaissance and scanning methods (such as DNS, Google searches, etc.).


### Preventing and Detecting IPv6 Tunneling
Many forms of IPv6 via IPv4 tunnels carry IPv6 where TCP or UDP would normally be

- The layer 3 header "Protocol" field would be 41 (IPv6) in this case
- Configure Next-Gen Firewalls, IDSes and/or IPSes to block/alert protocol 41, Snort syntax: `ip_proto:41`

### Unauthorized IPv6 Router Advertisements
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

### Network Segmentation Principles
- Segmentation should facilitate prevention & detection
- Systems and data with different classification levels (tiers) must reside in different zones
- Control points are implemented at ”gates” where all ingress & egress traffic is inspected and access control policies enforced
- Balance security with usability — Higher segmentation adds complexity and administrative burden. Insufficient segmentation can make the network indefensible

### Example of Tiers – Based on Criticality and Business Impact
- Tier 1:  Critical components to maintain operations, including domain controllers, exchange servers, and network infrastructure devices.
- Tier 2: Internal systems containing PII and associated data, including databases, sharepoint servers and other web servers.
- Tier 3: External facing data-providing services
### Router ACLs
- Modern routers provide layer 3/4 firewall capabilities 

- Modern Cisco routers support standard and extended ACLs

	Standard: filters on source only (layer 3)
	Extended: filters on source or destination, as well as based on ICMP types/codes and TCP/UDP ports

• ACLs may be inbound or outbound

	Inbound: applied to packets entering the router
	Outbound: applied to packets before routing a packet to an outbound interface

### Enforcing Segregation
Organizations are often faced with legacy systems that lack vendor support.

All access (including internal) to unsupported systems should be filtered. Options include:

- Host-based firewall
- VLAN ACLs
- Router or Firewall filtering

Another option: Velcro a tiny USB powered firewall to the device

### Proxy Types
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

### SSL Interception
Encryption blinds a proxy by default: Interception of traffic would cause errors and break sites. 

SSL Interception allows analysis of encrypted sites

- Requires proxy to act as a trusted certificate authority
- Proxy generates certificates per site accessed

### Proxy Deployment
Proxies are deployed in one of two modes

- Transparent - Traffic goes through proxy regardless of endpoint configuration
- Explicit - Endpoints must be configured to use the proxy

### Proxy Placement
Ideally, everything would go through an explicit proxy

- What about devices that do not support proxies?
- What about devices that enter and leave the network?

Segmentation should be considered for "dumb" devices

- And possibly use a transparent proxy to limit access. Systems supporting proxy need access to the proxy
- Through direct access via internal or VPN access
- Or via proxy in the cloud or internet facing DMZ system

### Securing SMTP

-   [Sender Policy Framework (SPF)](https://support.google.com/a/answer/33786): Specifies the servers and domains that are authorized to send email on behalf of your organization. [^4] 
-   [DomainKeys Identified Mail (DKIM)](https://support.google.com/a/answer/174124): Adds a digital signature to every outgoing message, which lets receiving servers verify the message actually came from your organization. [^4]
-   [Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://support.google.com/a/answer/2466580): Lets you tell receiving servers what to do with outgoing messages from your organization that don’t pass SPF or DKIM [^4]

###  Sender Policy Framework (SPF)

DNS record validates email sent from an authorized source • Based on authorized IP addresses

- Based on DNS domain information (A record, MX record) 
- Can specify no email comes from a specific sub-domain

### DomainKeys Identified Mail (DKIM) 

Uses digital signatures to validate email

- Means asymmetric keys (private + public) and hashing Keys are created for each selector (may just need one)
- Private key goes to email system(s)
- Public key saved in DNS TXT record under `_domainkey.domain.com`

### Domain-Based Message Authentication, Reporting, and Compliance (DMARC)
DMARC verifies domain authentication via SPF or DKIM

-  Can use SPF/DKIM to force alignment of visible From


DMARC policy dictates actions and protection level

- Policy – Monitor, Quarantine, Reject
- Alignment – Strict, Relaxed


### Intentional Email Modification
SMTP proxies and email systems can add to a message

- Disclaimer messages
- Custom headers or footer banners
- "This message came from an external source"
- "This message may be a phishing email acting as an executive"

Requires setting up rules to do X when Y is true

- If display name matches executive add phishing message
- If external source add external source message

### Zero Trust
**Trust nothing — Verify everything**

All traffic must be secured

- Traffic must be authenticated
- Traffic must be encrypted

Least privilege must be enforced

- Trust must be factored into least privilege
- Trust is no longer binary (yes or no)

All data flows must be known and controlled

All assets must be scanned, hardened, and rotated

### Variable Trust
With a zero trust architecture, trust must be earned can change dynamically. For example, a user accessing a PCI database needs enough trust to gain access. It is possible to quantify the trust requirements such as by giving user points for logging in with a username and password and using a known device and location. Yet access is not simply yes and no.

Access to a PCI, the database requires 40 points. Yet the user and device combination initially only add up to 30 points. Rather than denying the connection variable trust can prompt or require an additional piece to increase trust. In this example, the user is prompted for smart card authentication. Supplying a smart card gives another 20 points for a total of 50 points. 50 points are enough trust to access the PCI database, so access is granted. 

Keep in mind part of variable trust is continuously re-evaluating trust, so once access is granted, it is not permanently given. Also, the concept allows the trust to accumulate or be lost over time due to a user or device's behavior.

### Credential Rotation
- Strong password policy
- Password Auditing tools
- LAPS (Windows Servers)
- Group managed service accounts (Windows Servers)


### Securing Traffic: mTLS
Mutual TLS, or mTLS for short, is a method for [mutual authentication](https://www.cloudflare.com/learning/access-management/what-is-mutual-authentication/). mTLS ensures that the parties at each end of a network connection are who they claim to be by verifying that they both have the correct private [key](https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/). The information within their respective [TLS certificates](https://www.cloudflare.com/learning/ssl/what-is-an-ssl-certificate) provides additional verification. [^5]

![](/Screenshots/Pasted%20image%2020230213100821.png)

### Public Key Infrastructure (PKI)
Automation is critical to support zero trust

-  Private PKI allows automation of certificate deployment
-  With support for client and server certificates

Windows Server capable of significant PKI capabilities

- Automatic certificate enrollment via GPO and AD
- Certificate templates and restrictions
- Secure private key archival
- Hierarchical certificate authorities roles and services

![](/Screenshots/Pasted%20image%2020230213101222.png)

The initial certificate authority is a root CA. The root CA creates a self-signed certificate as it is the initial chain and beginning of a custom PKI. The CA can be used for issuing certificates but is highly recommended to be only used for issuing or renewing other certificate authorities. The other certificate authorities are used to issue certificates while keeping the root CA secure. How this is done is the root CA is typically offline meaning it is only used during issuance or renewal of a sub-level CA. This protects the private key that has ultimate trust.

Issuing certificate authorities remain online. However, there can be multiple levels of CAs. A basic deployment may just involve the root CA and a single online certificate authority acting as an issuing CA. This down-level CA would be a subordinate CA. But organizations that segment their workforce or assets may need fine-grained trust control. These organizations may implement what is called an intermediate CA. An intermediate CA sits between a root CA and a subordinate CA and can allow granular control such as restricting what subordinate CAs there are and what types of certificates can be deployed.

### Certificate Authority Types
Stand-Alone:

- Manual certificate creation
- Common for Linux shops
- Recommended for root or intermediate CAs
- Should be run off-line Or out-of-band

Enterprise (Windows Specific deployment):

- Requires domain membership
- Allows automatic enrollment
- Can be used for smart cards
- Requires AD access
- Thus, never run off-line
- Contains templates

### IPSec
- IPSec is a network layer protocol
- Works with application regardless of IPSec awareness 
- Works independently of TCP or UDP

| Layer | Protocol |
| --- | --- |
| Application | HTTP |
| Transport | TLS/SSL | 
| Internet | IPSec |

SSL/TLS operates at the transport layer. Where this comes into play is that an application must be configured to use and accept TLS as part of its supported transport mechanisms. The most common example is the application of HTTP. HTTP is often paired with TLS to form HTTPS. IPSec, on the other hand, is baked into the kernel and is processed by the Internet layer of communication. This allows IPSec to be used regardless of application awareness or without requiring the use of TCP or UDP. Because of this, IPSec is highly flexible and an amazing option for adding authentication and encryption support.

- Mitigates man-in-the-middle
- Authenticates all traffic

[What is IPsec? | How IPsec VPNs work | Cloudflare](https://www.cloudflare.com/en-gb/learning/network-layer/what-is-ipsec/)

### Network Access Control (NAC)
Network Access Control is a solution that provides real-time authorization for network access. NAC functions by integrating with networking gear such as a switch or wireless access point and providing some mechanism for authenticating a device before it has network access. However, the level of network access given can be dynamically controlled by a NAC solution. 

Just like zero trust requires, network access can be given, but the level of access can be adjusted based on user or device actions and behaviors. A NAC system controls this by dynamically placing users or systems on specific VLANs or dynamically applying network access control lists.

NAC solutions “authenticate” devices various ways:

- 802.1X Port Authentication (CSC 1.5 + 1.6) 
- MAC Address OUI (Organizationally Unique Identifier)
- DHCP Fingerprinting

### Inline vs. Out-Of-Band NAC
**Inline:**

When NAC is deployed inline, it means the NAC solution acts as the gateway for each VLAN. This allows central management and eases network complexity. However, it also introduces a potential point of failure. Inline NAC is only recommended when organizations do not have managed switches with 802.1X support.

![](/Screenshots/Pasted%20image%2020230213105043.png)

### Captive Portal
Ideally device passes initial authentication methods

- Captive portal can handle failed devices or users
- Design is flexible and dynamic
- Terms and conditions only
- Gives guest VLAN access
- AD authentication
- Provides limited production access

Captive portal could be forced even with authentication

### Network Agent
Zero trust uses the concept of a network agent for access 

- A network agent is a user and device combined.

The network agent is used to determine authorization:

- User + corporate laptop = what access?
- User + personal laptop = what access?
- User + corporate phone = what access?

### Planes of Authorization
Control plane is core of zero trust

- Handles central authentication and global policy
- Authorizes requests and authorizes access

Data plane handles connections

- Establishes connection mediums
- Provides switching and routing
- But only if control plane continues to authorize access

Ideally is one device but for practical reasons is multiple

### Micro Core and Perimeter (MCAP)
The use of a segmentation gateway allows the enforcement of micro core and perimeter (MCAP) trust zones. MCAP is the ability to group users and devices of similar trust levels to enforce access controls. MCAP is not bound by VLAN segmentation. For example, it is possible to have users and devices on the same subnet be split into separate MCAP zones.

Proper MCAP groups should be based on grouping based on similar application use and data access requirements. Grouping different levels of trust such as users accessing confidential data with users that access standard data is not recommended due to the chances of accidentally granting access to confidential data. Depending on the security device in use an MCAP may only be able to place logical access constraints to network connections traversing a layer three boundary. This means that host-based firewall filters are still necessary to secure layer two connections or implementing private VLANs.

### Inventory Automation
One of the main challenges with implementing a segmentation gateway is that most implementations focus on end user identification and control rather than device and user identification. In fact, many commercial solutions have limited or no capabilities to associate devices with rules. On an NGFW device identification is typically a service that when enabled will passively identify and inventory assets. 

Passive discovery does not provide accurate means of authenticating a device. Therefore, it does not require the zero trust model of verifying everything. 

Instead, an NGFW can be fed accurate inventory information. This slide demonstrates a simple python script that is setting up an address object in a FortiGate firewall. Address objects and groups can be created and manipulated with scripts and with API interfaces for most commercial vendor firewalls. While this task seems daunting, it is a fairly simple script. FQDN objects can also be used but should only be used if DNS is secure such as with Windows secure DNS implementation.

### Real-Time Device Inventory 
Automation is critical for cyber defense. The previous slide shows an example of using python to create address objects in a firewall. However, for firewall rules to work, they need to be as real-time and accurate as possible. If an organization is using NAC or VPN authentication to authorize access to the network, then scripts can be kicked off as an end result of passing authentication. For example, a VPN solution may support running a post task when a user connects to the network. This task could be to run the previous python script logic to update an address object. For this to work and be secure, the post-task would need to be supported on the server side of a NAC and VPN solution. 

Alternatively, logs from NAC and VPN systems could be sent to a centralized logging system such as a SIEM. Since this happens almost instantly, the logs could be used to trigger a script to be run using the information found in the logs within the SIEM. For multiple solution support, a SIEM is likely the best bet to pull this off.

### Dynamic Authorization
Abnormal conditions should be monitored and reacted to:

- Temporal - Access outside normal user window
- Geographical - Access from different location
- Behavioral - Access to resource user does not normally use
- Frequency - Last access or volume of device/user use
- Or number of requests over time

Deviation from norm may dictate additional checks

- Multifactor authentication
- Approval from manager or administrator


### Disable Direct Memory Access (DMA) Devices
Operating systems sometimes make use of direct memory access (DMA) to provide high-speed interfaces. Thunderbolt connections are an example. By using DMA, a Thunderbolt device can achieve high-speed data transfer. DMA functions by providing input and output directly to memory. DMA even bypasses the CPU to increase the overall speed. The problem with this is that a hardware device effectively has access to memory.

Attack tools allow abusing DMA. One such attack tool is inception2. Inception uses DMA to gain system or root access and works on Windows, Linux, and Mac. Worse yet, inception works against systems using full disk encryption. Remember, full disk encryption protects data at rest as well as the boot process. With full disk encryption an attacker can turn on the machine, but he or she gets stuck at the login screen. Inception uses DMA once the machine is active to take over the system thus gaining access regardless of if the system is using full disk encryption. 

Windows has a group policy called "Prevent installation of drivers matching these device setup classes." Enabling this and adding the entry d48179be-ec20-11d1-b6b8-00c04fa372a7 helps prevent attacks using Firewire or 1394 interfaces. Another group policy called "Prevent installation of devices that match these device IDs" should be enabled and set to PCICC_0C0A. This prevents the installation of plug and play devices that use the Thunderbolt controller. 

To secure a Mac device from DMA attacks, you should set an EFI password. Setting an EFI password disables raw DMA access. 


## Resources
- [Defensible Security Architecture & Engineering: Implementing Zero Trust for the Hybrid Enterprise Course | SANS SEC530](https://www.sans.org/cyber-security-courses/defensible-security-architecture-and-engineering/)
- [(46) Building a Secure OT Network | SANS ICS Concepts - YouTube](https://www.youtube.com/watch?v=5Pip8jcKZh0)
- [(46) Zero-Trust Networks: The Future Is Here - SANS Blue Team Summit 2019 - YouTube](https://www.youtube.com/watch?v=EF_0dr8WkX8)
- [(46) VLANs Explained | Cisco CCNA 200-301 - YouTube](https://www.youtube.com/watch?v=A9lMH0ye1HU)
- [Subnetting != Segmentation | LMG Security](https://www.lmgsecurity.com/pentest-subnetting-segmentation/)
- [(47) Network Architecture | SANS ICS Concepts - YouTube](https://www.youtube.com/watch?v=Ai2bxzJMuVI)
- [(47) How to Use Security Architecture to Build a Defensible ICS Network - SANS ICS Security Summit 2021 - YouTube](https://www.youtube.com/watch?v=ls_U_rg2oCg)
- [(47) Cloud Security Architecture, Automation, and Identity - YouTube](https://www.youtube.com/watch?v=PGBxUU61248)
- [Implement network segmentation patterns - Microsoft Azure Well-Architected Framework | Microsoft Learn](https://learn.microsoft.com/en-us/azure/architecture/framework/security/design-network-segmentation)
- [Azure Network Virtual Appliances Firewall architecture overview - Azure Architecture Center | Microsoft Learn](https://learn.microsoft.com/en-us/azure/architecture/example-scenario/firewalls/)
- [Best practices for network security - Microsoft Azure | Microsoft Learn](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [Azure — Difference between Azure ExpressRoute and Azure VPN Gateway | by Ashish Patel | Awesome Azure | Medium](https://medium.com/awesome-azure/azure-difference-between-azure-expressroute-and-azure-vpn-gateway-comparison-azure-hybrid-connectivity-5f7ce02044f3#:~:text=ExpressRoute%20provides%20direct%20connectivity%20to,services%20over%20the%20public%20Internet.)
- [DevGuide/01-Principles of Security Engineering.md at master · OWASP/DevGuide (github.com)](https://github.com/OWASP/DevGuide/blob/master/02-Design/01-Principles%20of%20Security%20Engineering.md)
- [Enhanced Security Admin Environment (ESAE) architecture mainstream retirement | Microsoft Learn](https://learn.microsoft.com/en-us/security/compass/esae-retirement)
- [Security Architecture Principles| GitLab](https://about.gitlab.com/handbook/security/architecture/#security-architecture-principles)
- [Security Architecture review process | GitLab](https://about.gitlab.com/handbook/security/architecture/review.html)
- [Security Architecture | GitLab](https://about.gitlab.com/handbook/security/architecture/#security-architecture-reviews)
- [Security Requirements for Infrastructure Development and Deployment | GitLab](https://about.gitlab.com/handbook/security/planning/security-development-deployment-requirements/)
- [Application Security Review Process | GitLab](https://about.gitlab.com/handbook/security/security-engineering/application-security/appsec-reviews.html)
- [GitLab Data Classification Standard | GitLab](https://about.gitlab.com/handbook/security/data-classification-standard.html)
****

[^1]: [Implementing Network Segmentation and Segregation | Cyber.gov.au](https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-network-segmentation-and-segregation#:~:text=What%20is%20network%20segmentation%20and,between%20specific%20hosts%20and%20services.)
[^2]: [7 Network Segmentation Best Practices to Level-up | StrongDM](https://www.strongdm.com/blog/network-segmentation)
[^3]: [VLAN vs Private VLAN - IP With Ease](https://ipwithease.com/vlan-vs-private-vlan/)
[^4]: [Help prevent spoofing and spam with DMARC - Google Workspace Admin Help](https://support.google.com/a/answer/2466580?hl=en)
[^5]: [What is mTLS? | Mutual TLS | Cloudflare](https://www.cloudflare.com/en-gb/learning/access-management/what-is-mutual-tls/)