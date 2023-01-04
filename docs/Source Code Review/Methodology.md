# Methodology
## Setup
- [ ]  Enable database query logging

- After checking unauthenticated areas, focus on areas of the application that are likely to receive less attention (i.e., authenticated portions of the application)

---
## Map The Application Routes
> for more specific info on each technology check the techolog's folder

---
## Identify & Map
- How Access Control is done on endpoints
- Map non-authenticated endpoints

---
## Identify Data Storage
### SQL
1. Identify a query, and check how it's structured 
2. Read on the documentation of the used library
3. Take extra note of what the documentation warns the developers against doing. Generally big red boxes of warning are always a quick wins
4. Is the query construction the same in all SQL statments?

### XML
1. Are External Entities Parsed?

---
## Sanitization Functions
1. Is the sanitization done using a trusted, open-source library?
2. is it a custom solution

---
## Look for dangerous Functions
- Technology Specific Dangerous Functions
- SQL Queries
- XML Usage
---
## Read the code throughly for
- Account Managment Related Functionality
	- Login
	- Register
	- Session Creation
	- Forget Password


## General Tips
- Use debug print statements in interpreted code
- Attempt to live-debug the target compiled application.