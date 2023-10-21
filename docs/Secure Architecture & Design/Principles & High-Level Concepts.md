# Principles & High-Level Concepts
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
- [Secure Product Design - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html#security-focus-areas)
- [(46) Improve Cloud Threat Detection and Response using the MITRE ATT&CK Framework - YouTube](https://www.youtube.com/watch?v=8Iducc0l5vI)

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
## Infrastructure security architecture

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
3.  All external communication MUST be encrypted in transit using up to date protocols and ciphers.
4.  All internal communication SHOULD be encrypted in transit if possible.

### Data Handling and Isolation

1.  Data [retention policies](https://about.gitlab.com/handbook/security/records-retention-deletion.html) MUST be followed.
2.  Data MUST be encrypted at rest.
    1.  Data MAY be encrypted using provider managed keys.
3.  Data of different types MUST be logically separated at rest.
4.  Virtual networks (for example, VPC in GCP) MAY be used as a mechanism for data and workload isolation.

Examples of different data types:

-   User content, such as repository contents or attachments
-   Production derived data, such as logs
-   DFIR (Digital Forensics and Incident Response) artifacts, such as system logs and disk images

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
## Resources
- [Shifting the Balance of Cybersecurity Risk: Principles and Approaches for Security-by-Design and -Default (cisa.gov)](https://www.cisa.gov/sites/default/files/2023-06/principles_approaches_for_security-by-design-default_508c.pdf)
- [Implementing Phishing-Resistant MFA (cisa.gov)](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)