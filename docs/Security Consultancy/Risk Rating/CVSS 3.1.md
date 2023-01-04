# CVSS 3.1
[CVSS v3.1 User Guide (first.org)](https://www.first.org/cvss/user-guide)

Changes between CVSS versions 3.0 and 3.1 focus on clarifying and improving the existing standard without introducing new metrics or metric values, and without making major changes to existing formulas. 

## CVSS User guide
Membership in FIRST is not required to use or implement CVSS. FIRST does, however, require that any individual or entity using CVSS give proper attribution, where applicable, that CVSS is owned by FIRST and used by permission. Further, FIRST requires as a condition of use that any individual or entity which publishes scores conforms to the guidelines described in this document and provides both the score and the scoring vector so others can understand how the score was derived.

## CVSS Measures Severity, not Risk
The CVSS Specification Document has been updated to emphasize and clarify the fact that CVSS is designed to measure the severity of a vulnerability and should not be used alone to assess risk.

Concerns have been raised that the CVSS Base Score is being used in situations where a comprehensive assessment of risk is more appropriate. The CVSS v3.1 Specification Document now clearly states that the CVSS Base Score represents only the intrinsic characteristics of a vulnerability which are constant over time and across user environments. The CVSS Base Score should be supplemented with a contextual analysis of the environment, and with attributes that may change over time by leveraging CVSS Temporal and Environmental Metrics. More appropriately, a comprehensive risk assessment system should be employed that considers more factors than simply the CVSS Base Score. Such systems typically also consider factors outside the scope of CVSS such as exposure and threat.


## 2.2. Changes to Attack Vector and Modified Attack Vector
The Attack Vector (AV) metric value Adjacent (A) has a limited usage, as defined in CVSS v3.0. Ambiguity over the attack vector for logically adjacent or trusted networks (MPLS, VPNs, etc.) is addressed by expanding the definition of Adjacent to include these _limited access_ networks.

### 2.3.1. Scoring Should Assume Detailed Knowledge

The CVSS Specification Document has been updated to clarify that, when scoring Base Metrics, it should be assumed that the attacker has advanced knowledge of the weaknesses of the target system, including general configuration and default defense mechanisms (e.g., built-in firewalls, rate limits, or traffic policing).

### 2.3.2. Score Based on Privileges Gained, not Attained

Additional text has been added to Section 2.3 of the Specification Document to clarify that only the increase in access, privileges gained, or other negative outcome as a result of successful exploitation should be considered when scoring the impact metrics of a vulnerability.

When scoring impact, CVSS analysts should consider the privileges the attacker has prior to exploiting a vulnerability and compare those to the privileges they have after exploitation. The change in privileges is then captured in the Impact Metrics, i.e., Confidentiality, Integrity and Availability.

Finally, when scoring a delta change in Impact Metric, the final impact should be used.

### 2.3.3. Assume Vulnerable Configurations

The explanation of Attack Complexity in CVSS v3.0 considers “the presence of certain system configuration settings”. This text has been removed from CVSS v3.1. If a specific configuration is required for an attack to succeed, the vulnerable component should be scored assuming it is in that configuration, providing it is a reasonable configuration. Unreasonable configurations are those that deliberately place the target in a vulnerable state, e.g., by disabling security features, or that conflict with documented configuration guidance, e.g., by using a non-default configuration that a product vendor explicitly states should never be used.

### 2.3.5. Scoring Vulnerabilities in Software Libraries (and Similar)

New guidance explains how to score the impact of a vulnerability in a library. Refer to Section 3.7 for more information.

## 2.6. Formula Changes
The formulas used to calculate Base, Temporal and Environmental scores have altered in the following ways:
- General Formula Restructuring
- Roundup Function Redefinition
- Change to ModifiedImpact Sub-formula in Environmental Metric Group

## 3.1. CVSS Scoring in the Exploit Life Cycle

When understanding when to score the impact of vulnerabilities, analysts should constrain impacts to a reasonable final impact which they are confident an attacker is able to achieve.

## 3.2. Confidentiality and Integrity, Versus Availability Impacts

The Confidentiality and Integrity metrics refer to impacts that affect the _data_ used by the service. For example, web content that has been maliciously altered, or system files that have been stolen. The Availability impact metric refers to the _operation_ of the service. That is, the Availability metric speaks to the performance and operation of the service itself – not the availability of the data.

## 3.4. Vulnerability Chaining

CVSS is designed to classify and rate individual vulnerabilities. However, it is important to support the needs of the vulnerability analysis community by accommodating situations where multiple vulnerabilities are exploited in the course of a single attack to compromise a host or application. The scoring of multiple vulnerabilities in this manner is termed Vulnerability Chaining. Note that this is not a formal metric, but is included as guidance for analysts when scoring these kinds of attacks.

When scoring a chain of vulnerabilities, it is the responsibility of the analyst to identify which vulnerabilities are combined to form the chained score. The analyst should list the distinct vulnerabilities and their scores, along with the chained score. For example, this may be communicated within a vulnerability disclosure notice posted on a web page.

Given A and B, chain C could be described as the chain of B → A,  
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H which combines the Exploitability of B, the scope is unchanged in both cases, and the Impact of A, because if one can exploit B and gain the code execution as a local user from it, then one has satisfied the prerequisite to subsequently launch A causing an impact from vulnerability A.

When a vulnerability in a component governed by one security authority is able to affect resources governed by another security authority, a Scope change has occurred. This typically happens either when the vulnerable component and impacted component are part of different systems (physical or logical) governed by different security authorities; or when an artificial boundary has been made to logically separate vulnerable and impacted components for security reasons (e.g., when executing a process in sandbox). When a security boundary mechanism separating components is circumvented due to a vulnerability and this causes a security impact outside of the security scope of the vulnerable component, a Scope change has occurred. In this case, the vulnerability usually resides in the component that implements or controls the security boundary since the vulnerability restricted to the component alone would not cause an impact outside of its scope, assuming the security boundary works as expected.

## 3.6. Vulnerable Components Protected by a Firewall

If a vulnerability is scored with an Attack Vector (AV) of Network (N) and the analyst has high confidence that the vulnerable component is deployed on a secure network unavailable from the Internet, Modified Attack Vector (MAV) may be scored as Adjacent, reducing the overall CVSS v3.1 score.

Example: MySQL Stored SQL Injection (CVE‑2013‑0375)

> Base Score: 6.4 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N
> 
> Environmental Score: 5.4 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/MAV:A

## 3.7. Scoring Vulnerabilities in Software Libraries (and Similar)
For example, a library that performs image conversion would reasonably be used by programs that accept images from untrusted sources over a network. In the reasonable worst-case, it would pass them to the library without checking the validity of the images. As such, an analyst scoring a vulnerability in the library that relates to the incoming data should assume an Attack Vector (AV) of Network (N), but explain this assumption in the summary of the vulnerability. If the library might run with normal privileges, having lower impact on the embedding implementation, or with high privileges, increasing the impacts, the analyst should assume high privileges while scoring the vulnerability in the library.

When scoring a vulnerability in a given implementation using the impacted library, the score must be re-calculated for that specific implementation. For example, if an implementation embeds the vulnerable library mentioned in the previous example, but only operates on local files, the Attack Vector (AV) would be Local (L). If the implementation that embeds this library does not invoke any of the faulty functions or does not support the mode that triggers that vulnerability, it would have no interface or attack vector to exploit the vulnerability. Thus, that vulnerability in the embedded library would have no impact on that implementation, resulting in a score for the given implementation of 0.

## 3.8. Multiple CVSS Base Scores

It is common for a vulnerability to be present on multiple product versions, platforms, and/or operating systems. In some circumstances, the Base metrics may differ on different product versions, platforms, and/or operating systems. For example, a hypothetical vulnerability is applicable to multiple operating systems produced by the same vendor. The Attack Complexity (AC) of this vulnerability on a legacy operating system is Low (L). However, a newer operating system has new inherent protection capabilities that change the Attack Complexity to High (H). This variance ultimately leads to different Base Scores for the same vulnerability on the two operating systems.

It is acceptable to score and publish multiple Base Scores for a single vulnerability provided each has additional language outlining the specific product versions, platforms, and/or operating systems that are relevant to the score. Values for all Base Score attributes (not only a pre-calculated Base Score) must be supplied for each affected product version, platform, and/or operating system using a standard format. In situations where multiple Base Scores are applicable but only a single score is provided, the highest Base Score must be utilized.

## 3.9. CVSS Extensions Framework

Opportunities exist to leverage the core foundation of CVSS for additional scoring efforts. For example, a proposal was presented to the CVSS Special Interest Group (SIG) to incorporate privacy into CVSS by overlaying combinations of CVSS Base and Environmental metrics to derive a Privacy Impact.

The following guidelines define a standard method of extending CVSS to include additional metrics and metric groups while retaining the official Base, Temporal, and Environmental Metrics. The additional metrics allow industry sectors such as privacy, safety, automotive, healthcare, etc., to score factors that are outside the core CVSS standard.

## 3.10. Attack Vector Considerations

When scoring Attack Vector, use Adjacent or Network (as appropriate), when a network connection is required for an attack to succeed, even if the attack is not launched over a network. For example, a local attacker may be able to trick a vulnerable, privileged, local program into sending sensitive data to a server of the attacker’s choosing over a network. As a network connection is required to gather the sensitive data this is scored with an Attack Vector of Network.

Vulnerabilities where malicious data is received over a network by one component, then passed to a _separate_ component with a vulnerability should be scored with an Attack Vector of Local. An example is a web browser that downloads a malicious office document, saves it to disk, and then starts a vulnerable office application which reads the saved file.

In cases where the vulnerable functionality is part of the component that receives the malicious data, Attack Vector should be scored as Network. An example is a web browser with a vulnerability in the browser itself, or a browser plugin or extension, that triggers when the malicious data is received.