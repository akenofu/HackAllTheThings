# DevSecOps
## Concepts
### Learning Resources
- [Interactive Application Security Testing (IAST) | Snyk](https://snyk.io/learn/application-security/iast-interactive-application-security-testing/)
- [Guide to Software Composition Analysis (SCA) | Snyk](https://snyk.io/series/open-source-security/software-composition-analysis-sca/)
- [Shift left vs shift right: A DevOps mystery solved (dynatrace.com)](https://www.dynatrace.com/news/blog/what-is-shift-left-and-what-is-shift-right/)
- [Shift left vs Shift right: When to use Which? | BrowserStack](https://www.browserstack.com/guide/shift-left-vs-shift-right)
- [What is Shift Left Testing & Security? (aquasec.com)](https://www.aquasec.com/cloud-native-academy/devsecops/shift-left-devops/)
- [DevSecOps - Code With Engineering Playbook (microsoft.github.io)](https://microsoft.github.io/code-with-engineering-playbook/continuous-integration/dev-sec-ops/)
- [OWASP Top 10 CI/CD Security Risks | OWASP Foundation](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [DevSecOps: Making Security Central To Your DevOps Pipeline (spacelift.io)](https://spacelift.io/blog/what-is-devsecops)
- [Unify the DevSecOps lifecycle with GitLab | GitLab](https://about.gitlab.com/stages-devops-lifecycle/#plan)
- [DevSecOps Introduction for beginners: Security in the SDLC - GitGuardian Blog](https://blog.gitguardian.com/devsecops-introduction-accelerating-software-development/)
[(45) AWS Summit ANZ 2021 - How to approach threat modelling - YouTube](https://www.youtube.com/watch?v=GuhIefIGeuA)

![](/Screenshots/Pasted%20image%2020230524114625.png)

### CI/CD Hardening
#### CICD-SEC-1: Insufficient Flow Control Mechanisms

Map your attack premieter. I recommend threat modelling your CI/CD pipleine - just like you would any other highlevel system.
- Can internal malicious actors push code and trigger the build pipeline?
- Automerging code to production if it meets certain rules?
- Can artifacts, libraries or build dependencies be used to execute code?
- Can pipeline code be modified and executed?

**Recommendations:**
- Ensure no single person can push code and deploy it simultaneously. Ensure at least one or more reviewer is needed before code is pushed and build. 

#### CICD-SEC-2: Inadequate Identity and Access Management 

Identities should not be:

- Overly permission: principle of least privilege
- Stale (not used)
- Local: these are hard to manage and secure
- External: the security premieter is shared with other organizations, as the current organization rules are not enforced on them.
- Self-registered: hard to keep track and enforce rules
- Shared between programmatic context and human users

**Recommendations:**
- For all identities in the system map the identity provider, level of permissions granted and level of permissions actually used
- Disable/Remove any identity which has surpassed the predetermined period of inactivity.
- Create dedicated accounts for each specific context
- Prevent employees from using any address not owned by the organization

#### CICD-SEC-3: Dependency Chain Abuse
The main attack vectors:

- Dependency confusion 
- Dependency hijacking 
- Typosquatting
- Brandjacking 

**Recommendations:**
- Whenever 3rd party packages are pulled from an external repository, ensure all packages are pulled through an internal proxy
- Disallow pulling of packages directly from external repositories. Configure all clients to pull packages from internal repositories
-   Enable checksum verification and signature verification for pulled packages.
- Prefer configuring a pre-vetted version or version ranges
**TBC*




## Tools
### SAST
- [microsoft/DevSkim: DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities. (github.com)](https://github.com/microsoft/DevSkim)
- [pmd/pmd: An extensible multilanguage static code analyzer. (github.com)](https://github.com/pmd/pmd)
- [returntocorp/semgrep: Lightweight static analysis for many languages. Find bug variants with patterns that look like source code. (github.com)](https://github.com/returntocorp/semgrep)

### Secret Scanning
#### Tutorials
- [User defined patterns for secret scanning - GitHub Checkout - YouTube](https://www.youtube.com/watch?v=-ToS56Qbfdo)
- [Credential Scanning Tool: detect-secrets - Code With Engineering Playbook (microsoft.github.io)](https://microsoft.github.io/code-with-engineering-playbook/continuous-integration/dev-sec-ops/secret-management/recipes/detect-secrets/)
#### tools
- [trufflesecurity/trufflehog: Find credentials all over the place (github.com)](https://github.com/trufflesecurity/trufflehog)
- [thoughtworks/talisman: Using a pre-commit hook, Talisman validates the outgoing changeset for things that look suspicious — such as tokens, passwords, and private keys. (github.com)](https://github.com/thoughtworks/talisman)



## Resources
- [DSOMM (owasp.org)](https://dsomm.owasp.org/)