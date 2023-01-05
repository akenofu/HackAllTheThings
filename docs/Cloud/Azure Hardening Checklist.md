# Azure Hardening Checklist
## Azure AD Hardening [^1]
- [ ] 
## Azure Hardening
- [ ] **Checkout Azure Security Center periodically for recommended security improvements, specially adapted to your enviroment** [^2]
- [ ] Encrypt Data at rest and in-flight [^2]

![](/Screenshots/Pasted%20image%2020230105000757.png)

- [ ] Restrict access to your databases, One or more of the following will suffice [^2]:
	- [ ] Configure Firewall rules for the database
	- [ ] Utilize [Azure Private Link](https://learn.microsoft.com/en-us/azure/private-link/private-link-overview). Checkout [Azure Security best practices](https://youtu.be/mntOLLNejUo?t=77)
- [ ] Restrict access to your VMs, , One or more of the following will suffice [^2]:
	- [ ] Configure Bastion Hosts
	- [ ] Use [Azure Bastion - Fully Managed RDP/SSH](https://azure.microsoft.com/en-gb/products/azure-bastion#:~:text=Azure%20Bastion%20is%20a%20fully,exposure%20through%20public%20IP%20addresses.)
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