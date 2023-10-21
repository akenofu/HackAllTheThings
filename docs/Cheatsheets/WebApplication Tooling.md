## Fuzzing
```bash
ffuf -u https://10.10.14.2/FUZZ -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt -fc 401
```


## VHost Discovery
```bash
./gobuster dir -u https://10.10.14.2 -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt --wildcard 401
```

## File/Dir Busting
```bash
# Dirbrute Forcing With extension
./feroxbuster --url https://10.10.14.2 --depth 2 --wordlist /opt/SecLists/Disc  
overy/Web-Content/raft-large-words.txt -k -C 401 -o ~/spectre/edge-https.feroxbuster -x php,pl,sh,asp,ht  
ml,json,py,cfm,aspx,rb,cgi,js,bak,txt

# Ffuf
ffuf -u https://102.128.176.162/FUZZ -w /mnt/security/Projects/WebScripts/output/special-chars.3.fuzz -fc 401
```

### Backup Discovery
```bash
# Backup discovery
bfac -u https://102.128.176.162/ -xsc 401
```

## Param Discovery
```bash
./x8 -u "https://10.10.14.2" -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```


## Tooling
- [X8](https://github.com/Sh1Yo/x8/)
- [bfac](https://github.com/mazen160/bfac)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [gobuster](https://github.com/OJ/gobuster)
- [ffuf](https://github.com/ffuf/ffuf)

