# Web Application and API Penetration testing
# Scope
- [ ] URLs: in-scope and out-of-scope
- [ ] Any pages/functionalities that the client does not want to be tested
- [ ] Application demo
- [ ] Dangerous functionalities or pages they specifically would like tested?
- [ ] Any pages that should not be tampered with?
- [ ] Is the application in development or production?
- [ ] Any sensitive functionality or configuration that could break the application when changed?
- [ ] If it's development, how hard should you go?
- [ ] Any complex workflows? If yes, a demo or workflow diagrams are needed
- [ ] APIs?
- [ ] Has it been tested before?
- [ ] Any new changes? Updates? new functionalities? New code introduces security vulnerabilities
- [ ] Any previous restest reports? any thing they would like retested?

# Access
- [ ] VPN required?
- [ ] Azure AD, Local Authentication, or AD accounts needed for login?
- [ ] WAF or other security controls; If yes, ask them to whitelist your IPs


# Accounts and roles
- [ ] Different roles available?
- [ ] Admin accounts?
- [ ] Are different accounts of the same role provided? Used to test Horizontal privilege escalation


# Architecture and technology
- [ ] Server configuration
	- [ ] Language: JS, Java, etc.
	- [ ] Framework: Laravel, Ruby on Rails, etc.
	- [ ] meta-framework E.g. NextJs, SvelteKit ,etc.
	- [ ] Database E.g. firebase, MSSQL, Redis, Mongoose, etc.
- [ ] Underlying infrastructure
	- [ ] Proxy servers
	- [ ] caching servers
	- [ ] CDNs
- [ ] Src code available? 
- [ ] Does the application utilize open-source-frameworks, Libraries, or projects on GitHub

## API
- [ ] OpenAPI Specification (Swagger) Files
- [ ] Postman collection or other similar automated testing tools