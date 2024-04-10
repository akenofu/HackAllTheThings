# Secrets Management
## Canary Tokens
- Generate [Canarytokens](https://www.canarytokens.org/generate)
- [TruffleHog Now Detects AWS Canaries without setting them off ◆ Truffle Security Co.](https://trufflesecurity.com/blog/canaries?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=tl-dr-sec-220-detecting-manual-aws-actions-ai-threat-models-living-off-the-false-positive)

## Where can you store source code?
From bad to okay to amazing practices
- Source Code
- Environment Variables
- Configuration management vaults, i.e, ansible vault
- Secrets Management Solution

## Components of Secrets Management Solutions
- secrets backend
- auth backend
- audit backend

## AppRole Authentication
![](/Screenshots/Pasted%20image%2020240330044011.png)
Without Trusted entities:
![](/Screenshots/Pasted%20image%2020240330044636.png)

With trusted entities:
![](/Screenshots/Pasted%20image%2020240330044705.png)
with people in the mix:
![](/Screenshots/Pasted%20image%2020240330045057.png)