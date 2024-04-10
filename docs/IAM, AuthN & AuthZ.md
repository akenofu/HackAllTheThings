# IAM, AuthN & AuthZ
## IAM
### Enforcing least privilege
- [Access: A New Portal for Managing Internal Authorization (discord.com)](https://discord.com/blog/access-a-new-portal-for-managing-internal-authorization?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=tl-dr-sec-225-xz-backdoor-github-cso-interview-specterops-con) A premier on authorization and access management
	- The product we ended up using should be designed to decrease risks associated with long-standing, elevated, and sometimes no-longer-needed permissions to protect our systems and customer data.
	
	- **We wanted an intuitive user experience that didn’t require staff to have deep knowledge of the access control tool or the systems being managed**. This would help ensure the tool’s adoption within the company
	
	- team members likely would not have enough context to make informed decisions about access and end up ‘rubber stamping’ requests. By delegating access approvals to application owners and people leads with the most understanding about the application or role and permissions being requested, we could reduce risk while distributing the load.
	
	- Users should be able to see what access they or their teammates have, what resources are controlled by the system, what permissions they had in the past but have since expired, and they should be able to request access to resources freely. This would empower employees to troubleshoot their own permissions and solve issues through access requests.
### Fundamentals
- [What is an identity provider (IdP)? | Cloudflare](https://www.cloudflare.com/en-gb/learning/access-management/what-is-an-identity-provider/)
- [What is identity and access management (IAM)? | Cloudflare](https://www.cloudflare.com/en-gb/learning/access-management/what-is-identity-and-access-management/)
- [What is Identity Access Management (IAM)? | Microsoft Security](https://www.microsoft.com/en-gb/security/business/security-101/what-is-identity-access-management-iam#:~:text=Identity%20and%20access%20management%20is,who%20need%20access%20have%20access.)
- [What Is Attribute-Based Access Control (ABAC)? | Okta](https://www.okta.com/blog/2020/09/attribute-based-access-control-abac/)
- [RBAC vs. ABAC: Definitions & When to Use | Okta](https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/)

## AuthN & AuthZ
### Kerberos
- [Quick Overview of Kerberos Authentication | by Nairuz Abulhul | R3d Buck3T | Medium](https://medium.com/r3d-buck3t/quick-overview-of-kerberos-authentication-318f4918b15)
![](/Screenshots/Pasted%20image%2020230910194154.png)
> Note that the account passwords in the previous diagram refers to the NTLM hash of the user password, not the clear-text password - as those are not stored on-desk in clear-text.
### SAML
- [What is SAML and how does SAML Authentication Work (auth0.com)](https://auth0.com/blog/how-saml-authentication-works/)
- [SAML AuthnRequest Examples | SAMLTool.com](https://www.samltool.com/generic_sso_req.php)

![](/Screenshots/Pasted%20image%2020230910181425.png)

### OAuth
- [OAuth grant types | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/oauth/grant-types)
- [What are the trade-offs between implicit grant flow and authorization code flow? (linkedin.com)](https://www.linkedin.com/advice/0/what-trade-offs-between-implicit-grant-flow-authorization)
#### Authorization Code Grant
![](/Screenshots/Pasted%20image%2020230910183343.png)
#### Implicit Grant
![](/Screenshots/Pasted%20image%2020230910183410.png)
### Resources
- [Things to Know about Authentication/Authorization protocols! | by umang goel | Medium](https://medium.com/@surfd1001/things-to-know-about-authentication-authorization-protocols-addff3654d97)

