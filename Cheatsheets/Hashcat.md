### Password Mutation
```bash
# Apply rules to hash while cracking
hashcat -m 0 bfield.hash /usr/share/wordlists/rockyou.txt -r rules

# Apply rules to wordlist to mutate it 
hastcat --stdout passwords -r /usr/share/hashcat/rules/best64.rule

# Identify hash mode
./hashcat --quiet '5f4dcc3b5aa765d61d8327deb882cf99'

# Identify Binary File hash mode
./hashcat --quiet /opt/example.hashes

```