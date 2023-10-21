# Salesforce Testing 
## Testing Write-ups
- [Pen-Testing Salesforce Apps: Part 1 (Concepts) | by Praveen Kanniah | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-1-the-essentials-ffae632a00e5)
- [Pen-Testing Salesforce Apps: Part 2 (Fuzz & Exploit) | by Praveen Kanniah | InfoSec Write-ups (infosecwriteups.com)](https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae)
- [Hacking Salesforce-backed WebApps - Hypn.za.net](https://www.hypn.za.net/blog/2022/11/12/Hacking-Salesforce-backed-WebApps/)
- [Abusing Privilege Escalation in Salesforce Using APEX (cloudsecurityalliance.org)](https://cloudsecurityalliance.org/blog/2020/07/16/abusing-privilege-escalation-in-salesforce-using-apex/)
- [Salesforce Lightning - An in-depth look at exploitation vectors for the everyday community - Enumerated - gigminds](https://blog.gigminds.com/salesforce-lightning-an-in-depth-look-at-exploitation-vectors-for-the-everyday-community-enumerated_1602201600000/)

## Code analysis Checklist
- [ ] Search for SOQL Injection using the following regex
	```regex
	\[.*SELECT.**[+] .*
	```
- [ ] Search for unsanitized rendered output, look for
	```
	escape="false"
	```
	Reference: [apex:outputText escape="false“ keyword by passing Security ? - Salesforce Developer Community](https://developer.salesforce.com/forums/?id=9062I000000IRXaQAO)
- [ ] Check if developer console is accessible
```http
https://<domain>.my.salesforce.com/_ui/common/apex/debug/ApexCSIPage
```

- [ ] Abuse `search in files` functionality to leak source code, passwords, tokens, etc.
	- [ ] SOQL Queries to leak data that might not be accessible and protected by Apex classes sharing permissions.



## Tools
- [Ophion-Security/sret: Salesforce Recon and Exploitation Toolkit (github.com)](https://github.com/Ophion-Security/sret)
- [moniik/poc_salesforce_lightning: Academic purposes only. Attack against 
Salesforce lightning with guest privilege. (github.com)](https://github.com/moniik/-poc_salesforce_lightning)

## VSCode
- [Salesforce Extension Pack (Expanded) - Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=salesforce.salesforcedx-vscode-expanded)
- [Set Up Visual Studio Code Unit | Salesforce Trailhead](https://trailhead.salesforce.com/content/learn/projects/quick-start-lightning-web-components/set-up-visual-studio-code)


## Learning Resources
- [Access Modifiers | Apex Developer Guide | Salesforce Developers](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_access_modifiers.htm)
- [Using the with sharing, without sharing, and inherited sharing Keywords | Apex Developer Guide | Salesforce Developers](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_keywords_sharing.htm)
- [Understanding With Sharing and Without Sharing In Salesforce - Brian Cline (brcline.com)](https://www.brcline.com/blog/understanding-with-sharing-and-without-sharing-in-salesforce)
- [Salesforce DX - App Cloud for Developers - Salesforce India](https://www.salesforce.com/in/products/platform/products/salesforce-dx/)

## Interesting reads
[VF Remoting Exploit - Salesforce Developer Community](https://developer.salesforce.com/forums/?id=9062I000000XvqIQAS)
## Burp Extensions
- [GitHub - akenofu/lightning-burp](https://github.com/akenofu/lightning-burp)
## Tips and tricks
- Look at the security settings page