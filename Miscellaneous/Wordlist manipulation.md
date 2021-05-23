### Password Mutation
```bash
# Apply rules to hash while cracking
hashcat -m 0 bfield.hash /usr/share/wordlists/rockyou.txt -r rules

# Apply rules to wordlist to mutate it 
hastcat --stdout passwords -r /usr/share/hashcat/rules/best64.rule
```