# Azure Hardening Checklist
- [ ] Disable App Registrations [^1]
![](/Screenshots/Pasted%20image%2020230105004025.png)
- [ ] Limit Enterprise applications, for information on possible abuses checkout, illicit consent grant attacks [^1] 
![](/Screenshots/Pasted%20image%2020230105004506.png)
- [ ] Restrict External collaboration access [^1]
![](/Screenshots/Pasted%20image%2020230105005514.png)
- [ ] Limit guest user access [^1]
![](/Screenshots/Pasted%20image%2020230105005557.png)
![](/Screenshots/Pasted%20image%2020230105005604.png)
- [ ] Enable 2FA or Microsoft Intune  for device enrollement to Azure AD [^1]
![](/Screenshots/Pasted%20image%2020230105005651.png)
- [ ] Review Network security groups (NSG) for overly permissive access (refer to your business needs) [^1]
- [ ] Apply primary deny on Network security groups [^1]
- [ ] Use virtual network service tags instead of hardcoding IPs to manage NSGs
- [ ] Ensure blob storages are set to private in production enviroments
![](/Screenshots/Pasted%20image%2020230105010536.png)
- [ ] **Checkout Azure Security Center periodically for recommended security improvements, specially adapted to your enviroment** [^2]
- [ ] Enable NSGs for non-VPN gateway subnets in your network; Enable NSGs for VPN gateway might lead to breakdown the access to your systems [^2]
- [ ] Test your Azure functions and Azure Applications for traditional application vulnerabilities e.g., SQLi, XXE, SSRF, etc. [^2]
- [ ] Review access controls to your Azure Apps to ensure no overly permissive access is permitted (refer to your business needs)
- [ ] Use Microsoft [CredScan](https://secdevtools.azurewebsites.net/helpcredscan.html) to identify leaked credentials and secerets
- [ ] Encrypt Data at rest and in-flight [^2]
![](/Screenshots/Pasted%20image%2020230105000757.png)

- [ ] Restrict access to your databases, One or more of the following will suffice [^2]:
	- [ ] Configure Firewall rules for the database
	- [ ] Utilize [Azure Private Link](https://learn.microsoft.com/en-us/azure/private-link/private-link-overview). Checkout [Azure Security best practices](https://youtu.be/mntOLLNejUo?t=77)
- [ ] Restrict access to your VMs, , One or more of the following will suffice [^2]:
	- [ ] Configure Bastion Hosts
	- [ ] Use [Azure Bastion - Fully Managed RDP/SSH](https://azure.microsoft.com/en-gb/products/azure-bastion#:~:text=Azure%20Bastion%20is%20a%20fully,exposure%20through%20public%20IP%20addresses.)
	- [ ] Remove the public IP address of machines that should not be exposed to the internet
	- [ ] Use Just-in-time VM access from azure [^1]
		![](/Screenshots/Pasted%20image%2020230105010230.png)
- [ ] Audit and Remove excessive Privileges Held by Service Principals [^4]
	- Global Administrator
	- Privileged Role Administrator
	- Privileged Authentication Administrator
- [ ] Additionally, audit for any Service Principals that have been granted any of the following MS Graph app roles [^4] :
	- RoleManagement.ReadWrite.Directory
	- AppRoleAssignment.ReadWrite.All
- [ ] Protect your secerets, consider using [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) [^2]
	- [ ] Store secerets in the Azure Key Vault
	- [ ] Use Managed Service Identities to connect to key vaults
- [ ] Use a seperate Azure Subscription for production: allows the use of multiple RBACs and policies to enforce controls only for the non-production enviroment [^2] .
- [ ] Configure a WAF, follow the steps below  [^2]:
	- [ ] Implement application gate way or front in front of your web application
	- [ ] Enable a web application firewall


[^1]: [Cloud Misconfiguration & Risks - Azure](https://misconfig.io/cloud-misconfiguration-risks-azure/)
[^2]: [Azure Security best practices | Azure Tips and Tricks - YouTube](https://www.youtube.com/watch?v=mntOLLNejUo)
[^3]: [Top 10 Best Practices for Azure Security - YouTube](https://www.youtube.com/watch?v=g0hgtxBDZVE)
[^4]: [Managed Identity Attack Paths, Part 1: Automation Accounts | by Andy Robbins | Posts By SpecterOps Team Members](https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a)