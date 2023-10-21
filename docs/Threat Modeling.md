
# Threat Modeling
Based on:
- [Threat Modelling Cloud Platform Services by Example: Google Cloud Storage | NCC Group Research Blog | Making the world safer and more secure](https://research.nccgroup.com/2023/01/31/threat-modelling-cloud-platform-services-by-example-google-cloud-storage/) (Recommended)
- [Threat Modeling Security Fundamentals - Training | Microsoft Learn](https://learn.microsoft.com/en-us/training/paths/tm-threat-modeling-fundamentals/)
- [Blog - Analysing vulnerabilities with threat modelling using diagrams.net](https://www.diagrams.net/blog/threat-modelling)
- [TON_ThreatModeling_1612.pdf (toreon.com)](https://www.toreon.com/wp-content/uploads/2016/12/TON_ThreatModeling_1612.pdf)
- [Microsoft Threat Modeling Tool - STRIDE - Usage and Examples - Cybersecurity Memo (51sec.org)](http://blog.51sec.org/2022/11/microsoft-threat-modeling-tool-stride_15.html) - Has good examples ✅
- [Threat Modeling Process | OWASP Foundation](https://owasp.org/www-community/Threat_Modeling_Process)
- [(45) AWS Summit ANZ 2021 - How to approach threat modelling - YouTube](https://www.youtube.com/watch?v=GuhIefIGeuA)
- [(46) Cloud Threat Modeling - from Architecture Design to Application Development - YouTube](https://www.youtube.com/watch?v=9IBgPOe8zrc)
- [(46) Introduction to Threat Modelling with STRIDE - YouTube](https://www.youtube.com/watch?v=X5pXetz52zI)
- [Threat modeling for builders (workshops.aws)](https://catalog.workshops.aws/threatmodel/en-US/introduction)
- [Threat modeling for builders - Stride Per Element (workshops.aws)](https://catalog.workshops.aws/threatmodel/en-US/what-can-go-wrong/stride-per-element)
- [Threat modeling for builders - Zones of Trust (workshops.aws)](https://catalog.workshops.aws/threatmodel/en-US/what-are-we-working-on/trust-boundaries#zones-of-trust)
- [How to approach threat modeling | AWS Security Blog (amazon.com)](https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/)
- [Improve Cloud Threat Detection and Response using the MITRE ATT&CK Framework - YouTube](https://www.youtube.com/watch?v=8Iducc0l5vI)
- [MR201610_STRIDE_Variants_and_Security_Requirements-based_Threat_Analysis_ENG.pdf (ffri.jp)](https://www.ffri.jp/assets/files/monthly_research/MR201610_STRIDE_Variants_and_Security_Requirements-based_Threat_Analysis_ENG.pdf)
- [(45) AWS Summit ANZ 2021 - How to approach threat modelling - YouTube](https://www.youtube.com/watch?v=GuhIefIGeuA)

## When to use threat modeling

Use threat modeling whenever you design new systems or update existing ones. Examples include:

-   Creating a new Azure micro-service that reports on your organization's cloud resource usage for budgeting purposes
-   Designing a public API to provide customers access to your data
-   Adding a new feature to an existing application

## Threat Modeling Phases
![](/Screenshots/Pasted%20image%2020230304222120.png)
![](/Screenshots/Pasted%20image%2020230304222203.png)
### Step 1 - Design

#### Goals

-   Develop a clear picture of how your system works
-   List every service consumed by your system
-   Enumerate all the assumptions about the environment and default security configurations
-   Create a data-flow diagram using the right context depth level

#### Ask questions about your system
[Step 1 - Design - Capture Requirements and Create a Data-Flow Diagram - Training | Microsoft Learn](https://learn.microsoft.com/en-us/training/modules/tm-introduction-to-threat-modeling/2-step-1-design-phase#Ask%20questions%20about%20your%20system)

#### Create a data-flow diagram

Use the answers to create a data-flow diagram. Your diagram shows data across each stage in the data lifecycle, and includes changes in trust zones. Examples include:

-   Human users signing into your web application hosted in Azure to access data
-   Administrators changing default security configurations for elastic resources used by the web application
-   Automated daily scripts that monitor activity logs for the web application and notify administrators of any anomalies

A data-flow diagram shows the flow of data in a given system. It usually starts with requests from users or data stores and ends with data stores or Analytics Services. The data-flow diagram uses distinct shapes to indicate the elements they represent.

#### Information to include in the data-flow diagram
The amount of information to include in the data-flow diagram depends on a few key factors:

- Type of system you're building
	Systems that don't handle sensitive data or are used only internally may not need as much context as an externally facing system
- Required context from your security team
	Security teams are precise with what they look for in threat models. Speak with your security team to confirm the required depth layer

#### Diagram layers
To help you understand how much information to include, choose between these four context depth layers:
![](/Screenshots/Pasted%20image%2020230304223501.png)
> Most data-flow diagrams should contain **both Layers 0 and 1** depth layers. Speak with your security team to confirm the required layer depth.


### Step 2 - Break

The break phase is where you use the data-flow diagram to find potential threats against your system. The process uses a threat-modeling framework to help you find the most common threats and ways to protect against them.

#### Goals
The break phase is where you use the data-flow diagram to find potential threats against your system. The process uses a threat-modeling framework to help you find the most common threats and ways to protect against them.

- Choose between "protecting the system" or "understanding the attacker" focused approaches
- Use the STRIDE framework to identify common threats (described below)

Start by choosing whether you want to find ways to protect your system, or you want to understand all you can about an attacker and their motives. Examples include:
![](/Screenshots/Pasted%20image%2020230304223739.png)
> Microsoft product engineers mostly focus on protecting the system. Penetration testing teams focus on both.

#### STRIDE
![](/Screenshots/Pasted%20image%2020230304223830.png)

### Step 3 - Fix

The fix phase is where the fate of all threats is decided. Each STRIDE threat maps to one or more security controls, which offer different functions and types to choose from.

#### Prioritize threats

- **Impact**
Uses STRIDE categories to assign impact
- **Severity**
Uses internal bug bar or prioritization framework to assign severity using worst-case scenarios
- **Risk**
Uses a calculation of security control effectiveness and implementation cost

#### Rate threat effectiveness and cost
Visit each security control recommendation mapped to STRIDE threats. Write down the ones that are most effective and least expensive to implement. Here are a few examples:
![](/Screenshots/Pasted%20image%2020230305125710.png)

#### Security control types and functions
Security controls have different types and functions. When combined, they help secure your system and create multiple layers of security, also known as defense-in-depth.

They may have one or more security control functions:
![](/Screenshots/Pasted%20image%2020230305125950.png)

#### Add security control details to each issue
Add the details to each issue in the bug management solution, then resolve each issue with one of the following resolutions. They'll vary slightly from organization to organization:
![](/Screenshots/Pasted%20image%2020230305130045.png)

### Step 4 - Verify
The verify phase is the last step of the threat-modeling process, which often happens before the system is deployed. It involves ensuring requirements are met, assumptions are validated, and security controls are in place.

#### Goals

-   Confirm all previous and new security requirements are satisfied for the system
-   Configure cloud provider, operating system, and components to meet security requirements
-   Ensure all issues are addressed with the right security controls
-   Take system through manual and automated verification before deployment

#### Verify requirements and set defaults
1. Start by verifying all requirements created in the first phase are met. Examples:

	-   Network security plans
	-   Secrets-management solution implementation
	-   Logging and monitoring systems
	-   Identity and access controls

2. Then make sure the default configuration settings from the cloud provider, operating system, and components are changed to meet all security requirements. Examples:

	-   Enable Azure SQL Database transparent data encryption to protect data on disk
	-   Use Role Based Access Control (RBAC) to assign permissions to users, groups, and applications
	-   Enable Windows Firewall across all profiles

#### Run verification
The last part involves running both manual and automated verification. At Microsoft, systems are subject to a verification process before deployment, and may consist of automated scanners, code reviews, and penetration tests. The process can be enforced before each deployment or across time intervals, like every **6-12 months**.

If you answer **yes** to any of the following questions, you may want to have shorter verification cadences:

-   Will my system be used externally?
-   Does it handle confidential data?
-   Do I have to comply with regulations?
-   Does my organization require additional security processes such as privacy implications, operational risk, or development requirements?

## Data flow diagrams
### Process Elements
#### When to use the process element
![](/Screenshots/Pasted%20image%2020230305132329.png)

#### Include context
Include the following context to each process element:
![](/Screenshots/Pasted%20image%2020230305132438.png)
### Storage elements
#### Include context
Include the following context to each data store element:
![](/Screenshots/Pasted%20image%2020230305132655.png)

### External entity  Elements
Depicted by a square, an external entity can be a process, data store, or even a full-fledged system outside of your direct control.

Examples include:

-   A user interacting with your service
-   Tight integration with a third-party authentication service
-   Services created by other teams within your organization

#### When to use the external entity element

-   To represent what you can't directly modify
-   Data stores and external entities start the data flow, so verify you have either one in place

#### Include context
Include the following context to each external entity element:
![](/Screenshots/Pasted%20image%2020230305132836.png)

### Data-flow
#### When to use the data-flow element
-   Between each element interaction
-   Call out the data type being transmitted and include how you're transmitting it
-   In most cases, include responses to each request

#### Include context
Include the following context to each data-flow element:
![](Screenshots/Pasted%20image%2020230305133044.png)

### Trust boundary
Represented by dotted lines or squares, trust boundaries are used to describe data flow as it crosses different trust zone levels.

Examples include:

-   Firewalls
-   Connections to third-party services
-   Parts of your system only available to administrators

Areas with changing are the most targeted by attackers, and should be carefully designed.

#### Zones of trust
A system can be divided into zones of trust that are separated by boundaries. For example, a process that receives input from an external entity is likely in a different zone than a data store that keeps confidential data. Within a zone of trust, all elements are considered to be equally or similarly trusted. While each identified zone may be trusted differently, that does not imply more or less trust. Often, security controls (mitigations) are most usefully applied at trust boundaries to maintain the security properties of a system. The standard convention for drawing trust boundaries is a dashed line indicating where the separation exists.

#### Sample trust boundaries
**Externally-facing**
- A web server between the external user's web browser and service business logic.
- API endpoints between the external software development kit (SDK) or command line interface (CLI) client and serverless functions performing backend processing.

**Internally-facing**
- A single page application (SPA) HTML/JavaScript served from an Amazon Simple Storage Service (S3) bucket that then calls to a non-relational database.
- A user-space process and kernel-space driver within a running Amazon Elastic Compute Cloud (EC2) instance.

#### When to use the data-flow element
Here are a few important points to remember about trust boundaries:

-   Include trust boundaries to handle data flow as it crosses different trust zones
-   Trust boundary **lines** represent data flow as it crosses large environments, like the internet
-   Trust boundary **boxes** represent smaller environments, like sandbox environments and corporate networks

#### Include context
![](/Screenshots/Pasted%20image%2020230305133319.png)

### Example
![](/Screenshots/Pasted%20image%2020230305140050.png)

## Provide context with the right depth layer

### The importance of depth layers

Threat models can either get too complex or too high-level, depending on the system you're building and the required context.

Data-flow diagram depth layers help you understand how much context to include. In this module, you'll learn about data-flow diagram depth layers and when to use them.

### Data-flow diagram depth layers
Data-flow diagram depth layers can help you decide how much context to include for a successful threat-modeling exercise. There are many factors that can help you decide into how much depth you should go.

Every system should have a high-level overview of how it works. Most should have additional data-flow diagrams focusing on parts of the system that need a closer look.

Examples include:

-   A process parsing highly sensitive data
-   Third-party authentication systems

![](/Screenshots/Pasted%20image%2020230305133849.png)

### Layer 0 - The system layer
The system layer of data-flow diagrams is the starting point for any system. You need to create it for all your systems.
### Layer 1 - The process layer
The process layer of data-flow diagrams is the second layer. You should use it for most systems. Data-flow diagrams at this layer contain separate data-flow diagrams detailing each system part. This could be a process or an application.
### Layer 2 - The subprocess layer
The subprocess layer of data-flow diagrams is the third layer. You should use it whenever you create systems that are highly sensitive. Data-flow diagrams at this layer contain separate data-flow diagrams detailing each system subpart. This could be a parser that's part of an application.

>Create a new file and name it exactly the same as the description label, with a tree-like structure, such as _Web Service Name - Web Service Worker Name - Input Parser Name_.

### Layer 3 - The lower-level layer
The lower-level layer is the last layer, and you should use it whenever you create a kernel-level or critical level system. Data-flow diagrams at this layer contain separate data-flow diagrams detailing each low-level system subpart.

#### When to use the lower-level layer
Highly critical systems and kernel-level systems should be threat modeled at this layer. Data-flow diagrams should describe each subprocess in minute detail. Also, it's common to have multiple rounds of security reviews just for one subprocess.


## Approach your data-flow diagram with the right threat model focus
-   Define a system-focused threat modeling exercise.
-   Explain the high-level differences between the system-, asset-, and attacker-focused approaches.

### System-focused approach
Your goal is to protect the entire system. Here, you look at each process, data store, data-flow, external entity, and trust boundary. With this information, you'll select security controls to help protect your system.

The framework helps you analyze the system and how it affects other assets, which include:
![](/Screenshots/Pasted%20image%2020230305140357.png)

### Attacker-focused approach
In the attacker-focused approach, you emphasize the attacker, their motive, means, and all the ways they can wreak havoc in your system. This approach looks at entry points, rather than the system as a whole.

This approach allows you to focus on critical assets holding highly confidential data for your system. Emphasis is placed on protecting those assets instead of the entire system.

### Asset-focused approach
Here, you'll evaluate risk for each asset. This approach identifies critical assets based on things like classified data handling, and focuses mostly on protecting those assets.

## Threat modeling framework
Each threat category is associated with a security control to help you reduce or eliminate risk:
![](/Screenshots/Pasted%20image%2020230305152606.png)

### Spoofing - pretending to be someone or something else
#### Common security controls to reduce or eliminate risk

For your data:

-   Hashes
-   Message Authentication Codes
-   Digital Signatures

For your system:

-   User Authentication
-   Cookie Authentication
-   Kerberos
-   SSL/TLS
-   Certificates
-   IPSec
-   Digitally Signed Packets

### Tampering - changing data without authorization
#### How to prevent tampering

**Integrity** prevents data from being maliciously modified. Examples include:

-   Validating input to prevent the processing of malicious payloads and mishandling of unexpected behavior
-   Signing messages with digital signatures to ensure messages aren't tampered with
-   Using access-control lists to apply permissions
-   Using SSL/TLS to secure transmission
-   Creating an IPSec tunnel to secure communication between endpoints

### Common security controls to reduce or eliminate risk

-   Operating system integrity controls
-   Access control lists (ACL)
-   Digital signatures
-   Message authentication codes

### Repudiation - not claiming responsibility for an action taken
**Repudiation** occurs when someone, with or without malicious intent, takes an action but claims otherwise.

Examples include:

-   Denying the modification of logs containing sensitive actions
-   Using someone else's account to avoid getting caught
-   Claiming not to have deleted database records

#### Common security controls to reduce or eliminate risk
- Strong authentication
- Secure logging and monitoring
- Digital signatures
- Secure timestamps
- Trusted third parties

### Information disclosure - seeing data I am not supposed to see
**Information disclosure** occurs when sensitive data is exposed to unauthorized individuals. It can happen with or without intention.

Examples include:

-   System reveals sensitive data through error messages
-   Users access unauthorized documents and folders with weak security controls
-   Users access data flowing through an unsecured network

#### How to prevent information disclosure

**Confidentiality** ensures data is protected.

Examples include:

-   Applying access-control lists to ensure the right users can access the right data
-   Encrypting data at rest, in transit, and in use
-   Enforcing SSL/TLS to secure transmission
-   Using IPSec tunnels to secure communication across endpoints

#### Common security controls to reduce or eliminate risk

-   Encryption
-   Access Control Lists (ACL)

### Denial of Service - overwhelming the system
**Denial of service** occurs when an attacker causes the system to be unavailable.

Examples include:

-   Flooding the network with requests
-   Absorbing memory and CPU processes
-   Crashing data stores with an overwhelming number of requests

#### How to prevent denial of service

**Availability** ensures your system is up and running for users. Examples include:

-   Using network access-control lists to control incoming and outgoing traffic
-   Using elastic resources to manage growing or shrinking usage
-   Monitoring the system to detect anomalies
-   Enabling operating-system flags to handle memory and CPU processes

#### Common security controls to reduce or eliminate risk

-   Access control lists (ACL)
-   Filtering
-   Quotas
-   Authorization
-   High availability

### Elevation of privilege - having permissions I should not have
**Elevation of privilege** occurs when individuals access resources without permission. Examples include:

-   Extracting data by exploiting weaknesses in input-handling logic or memory
-   Finding and using privileged accounts to corrupt the service (used in combination with spoofing and tampering threats)

#### How to prevent elevation of privilege

**Authorization** ensures users have proper permissions. Examples include:

-   Implementing authorization mechanisms to verify permissions to data and resources
-   Applying security controls to run the service using the least possible amount of access
-   Monitoring access to detect anomalies and unauthorized access attempts

#### Common security controls to reduce or eliminate risk

-   Access-control lists (ACL)
-   Role-based access controls (RBAC)
-   Group-based access
-   Permissions
-   Input validation


## Prioritize your issues and apply security controls
Threat modeling provides you with a list of threats and ways to reduce or eliminate risk, but it doesn't prioritize them for you. Also, there are no layered security control recommendations based on their type and function.

### Types and functions

Security controls have different types and functions.

There are three main types of security controls that are meant to help you look at three different forms of security.

Examples include:

-   **Physical**: Cameras, badges, and fences
-   **Technical**: Encryption, virtual firewalls, and antivirus
-   **Administrative**: Policies, regulations, and written requirements

Functions are meant to help protect your system against each phase of a potential threat.

Examples include:

-   Preventing break-ins with locks
-   Installing cameras to detect break-ins in process
-   Enacting a response plan to correct the break-in
-   Repairing the damage caused by the break-in
-   Deterring future break-ins with signs and additional security controls

### Prioritising the right controls
After you determine a priority for each issue, check out the list of security controls and select the options that provide the most benefit for your system.

The most beneficial security controls are found across multiple STRIDE categories. In most cases, they're also relatively inexpensive to implement.


## Security-control functions

Along with the three main types, security controls also have five different functions to help you apply multiple layers of security.
![](/Screenshots/Pasted%20image%2020230312104334.png)

### How it all comes together

Together with the security-control types, security-control functions create a matrix that helps you make the right selections. Here are a few examples:

![](/Screenshots/Pasted%20image%2020230312104728.png)

## Threat modeling tooling
Published by Microsoft and recognized by the threat-modeling community, the Microsoft Threat Modeling Tool helps engineers create data-flow diagrams and apply STRIDE for their threat-modeling work.

The Threat Modeling Tool offers:

-   Customizable templates
-   Threat-generation engine with threats and risk-reduction strategies

The default template is called "SDL TM Knowledge Base" and gives you a basic set of elements and threat-generation capabilities. All you need is a basic understanding of data-flow diagrams and STRIDE.

## Stride Per Element
Based on:
[Threat modeling for builders (workshops.aws)](https://catalog.workshops.aws/threatmodel/en-US/what-can-go-wrong/stride-per-element)

![](/Screenshots/Pasted%20image%2020230601164558.png)

## Stride Per Interaction

![](/Screenshots/Pasted%20image%2020230601165047.png)

## Planes of operations
Based on: [Threat modeling for builders (workshops.aws)](https://catalog.workshops.aws/threatmodel/en-US/what-can-go-wrong/reference-data-flow-diagram#planes-of-operations)

Control/administrative planes are used to configure the environment. For example:

- Creating EC2 instances,
- Configuring identity and access management (IAM) policies, and
- Adding or changing table metadata in DynamoDB.

The data/request plane is responsible for delivering real-time service. For example:

- Accessing and using EC2 instances,
- Assuming an IAM role to perform actions in your AWS account, and
- Performing DynamoDB table read/write operations.

## Tools
- [threat-composer (awslabs.github.io)](https://awslabs.github.io/threat-composer/?mode=ThreatsOnly)
- [Microsoft Threat Modeling Tool overview - Azure | Microsoft Learn](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)