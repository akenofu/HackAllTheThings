# Azure Assessment Checklist
## Manual Checks
- Check domains for subdomain takeovers
	- [Prevent subdomain takeovers with Azure DNS alias records and Azure App Service's custom domain verification | Microsoft Learn](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)
- Check for Azure resources using released elastic IPs
	- [Monitoring Your Assets in the Face of Emerging Cloud-Squatting Attacks | TikTok for Developers](https://developers.tiktok.com/blog/cloudsquatting-attack-explanation-and-mitigation-system-design)
- Check for applications loading resources that are no longer controlled by us
	-  [Monitoring Your Assets in the Face of Emerging Cloud-Squatting Attacks | TikTok for Developers](https://developers.tiktok.com/blog/cloudsquatting-attack-explanation-and-mitigation-system-design)
- Check for App Service Redirect URI takeover
	- [Azure Redirect URI Takeover Vulnerability | Secureworks](https://www.secureworks.com/research/azure-redirect-uri-takeover-vulnerability)
- Check Function/Logic apps for second order SQLi and not so subtle bugs
- Check teams and internal wiki for secrets 
- Check SharePoint sites and their security settings
- Check Azure DevOps for CI/CD attacks
- Map resources that are use by both production and test environments; These could be a security issue as the environments are not isolated enough - lateral movement may be possible.
- Check Microsoft SharePoint sites, teams and OneDrive settings for guest users
	[Governance of Teams guest users - Azure Architecture Center | Microsoft Learn](https://learn.microsoft.com/en-us/azure/architecture/example-scenario/governance/governance-teams-guest-users)
- Review conditional Access Policy from Entra Id
	- [What is Conditional Access in Microsoft Entra ID? - Microsoft Entra ID | Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
	- If not set, is device code phishing applicable? [Protect your users from Device Code Flow abuse - Cloudbrothers](https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/)
- Review public blob storage in a public storage account that has everything else as private
- Review who has access to BitLocker keys (Help Desk Support, Security Readers, etc...)
- Check for overly-permissive consent settings in https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings.
- Check for overly-permissive guest settings in https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserSettings.ReactView.

## Automated Checks:

- CIS Benchmarks for configuring resources securely, i.e,
	- Public Storage Containers
	- Overly permissive Network Security Group rules
	- Lack of secret vault use and hardcoded secrets
- IAM Misconfigurations
	- Check nested business groups

** Tools **

- [BloodHoundAD/AzureHound: Azure Data Exporter for BloodHound (github.com)](https://github.com/BloodHoundAD/AzureHound)
- [nccgroup/ScoutSuite: Multi-Cloud Security Auditing Tool (github.com)](https://github.com/nccgroup/ScoutSuite)
- [prowler-cloud/prowler: Prowler is an Open Source Security tool for AWS, Azure, GCP)](https://github.com/prowler-cloud/prowler)
#### Useful URLs

- https://portal.azure.com (Azure)
- https://aad.portal.azure.com/ (Entra ID formerly Azure AD)
- https://portal.office.com/Adminportal/Home (SharePoint Sites)
- https://www.office.com/signin (Office365)
- https://teams.microsoft.com/_?culture=en-us&country=ww (Microsoft Teams)

## Enumerate your permissions (The Lazy way)
1. Checking logged in User's self permissions

	You can ask the relevant user to Log into the Azure portal -> Click on the User logo on the top right corner of the screen -> select the elipsis (...) -> select "My permissions". [![enter image description here](https://i.stack.imgur.com/2dnLb.png)](https://i.stack.imgur.com/2dnLb.png)
	This will list all the permissions that user has in the Azure portal.

2. Checking Access Control (IAM) in the resource or resource group / subscription level.

	see : [https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access#step-2-check-access-for-a-user](https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access#step-2-check-access-for-a-user)
	[![enter image description here](https://i.stack.imgur.com/Rx0V0.png)](https://i.stack.imgur.com/Rx0V0.png)
	
1. Entra ID -> check your groups, check active assignments from the side blade
