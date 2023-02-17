# Azure best practices for network security

From: [Best practices for network security - Microsoft Azure | Microsoft Learn](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)

- [ ] Logically segment subnets
- [ ] Don't assign allow rules with broad ranges (for example, allow 0.0.0.0 through 255.255.255.255).
- [ ] Segment the larger address space into subnets.
- [ ] Create network access controls between subnets. Routing between subnets happens automatically, and you don't need to manually configure routing tables. By default, there are no network access controls between the subnets that you create on an Azure virtual network
- [ ] Use a network security group to protect against unsolicited traffic into Azure subnets. Network security groups (NSGs) are simple, stateful packet inspection devices.
- [ ] Avoid small virtual networks and subnets to ensure simplicity and flexibility.
- [ ] Simplify network security group rule management by defining Application Security Groups.
	- [ ] Define an Application Security Group for lists of IP addresses that you think might change in the future or be used across many network security groups. Be sure to name Application Security Groups clearly so others can understand their content and purpose.
- [ ] Give Conditional Access to resources based on device, identity, assurance, network location, and more.
- [ ] Enable port access only after workflow approval (You can use just-in-time VM access in Microsoft Defender for Cloud)
- [ ]  Grant temporary permissions to perform privileged tasks, which prevents malicious or unauthorized users from gaining access after the permissions have expired (Azure AD Privileged Identity Management).
- [ ] Configure [user-defined routes](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview#custom-routes) when you deploy a security appliance for a virtual network.
- [ ] Use virtual network appliances
	- [ ] Firewalling
	- [ ] Intrusion detection/intrusion prevention
	- [ ] Vulnerability management
	- [ ] Application control
	- [ ] Network-based anomaly detection
	- [ ] Web filtering
	- [ ] Antivirus
	- [ ] Botnet protection
- [ ] Deploy perimeter networks for security zones
	- [ ] A perimeter network is where you typically enable distributed denial of service (DDoS) prevention, intrusion detection/intrusion prevention systems (IDS/IPS), firewall rules and policies, web filtering, network antimalware, and more.
- [ ] Disable RDP/SSH Access to virtual machines
	- [ ] Enable a single user to connect to an Azure virtual network over the internet.
	- [ ] Point-to-site VPN
	- [ ] Just-in-time access
- [ ] Secure your critical Azure service resources to only your virtual networks
	- [ ] Use Azure Private Link to access Azure PaaS Services


 [Zero Trust](https://www.microsoft.com/security/blog/2018/06/14/building-zero-trust-networks-with-microsoft-365/) networks eliminate the concept of trust based on network location within a perimeter. Instead, Zero Trust architectures use device and user trust claims to gate access to organizational data and resources. For new initiatives, adopt Zero Trust approaches that validate trust at the time of access.