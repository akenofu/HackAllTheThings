# Automation
- These notes are gathered from our field pentests. It contains scripts to automate mass vulnerability scanning of some of the low hanging fruit we find around in massive networks.

## Host Discovery
```bash
# Need to use XML output and do it in a cleaner way, for now this works
nmap -sn 10.33.0.0/16 -oN 10.33.0.0-alive.nmap -v

# Consider using wc -l with the following command and the count of alive hosts from nmap to ensure you got all the hosts. Sometimes, nmap's output is inconsistent in terms of formatting
cat 10.33.0.0-alive.nmap  10.32.0.0-alive.nmap | grep -v 'host down' | grep -v 'Nmap done' | grep -v 'Host is up' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u 
```

## DNS
```bash
# resolve ips for all domains
for i in $(cat domains.txt); do dig +short $i ; done  | sort -u

# extract domains from web servers FQDNs
cat fqdns.txt | cut -d '.' -f 1  --complement | sort -u
```

## HTTP
```bash
# hosts.txt file content is a list of ips, seperated by a line break
# Identify alive
httpx -l hosts.txt -silent -probe -o web-servers_alive.httpx 

# One command to rule them all
httpx -l ips.txt -tech-detect -server -favicon -title -jarm -silent -fr -probe -ports http:80,8080,443 https://80,8080,443 -o ips-80_443_8080.httpx 

# Tested using root, you may need to su to root
nuclei -fr -headless -iserver <host> -itoken <token> -l alive.txt | tee nuclei.txt
```


## SMB
```bash
for i in $(cat ips-255.txt); do crackmapexec smb -u 'anonymous' -p 'anonymous' $i ;done | tee ips-SMB_ANON_LOGIN.cme

for i in $(cat ips-255.txt); do crackmapexec smb -u '' -p '' $i  --shares ;done | tee ips-SMB_NULL_AUTH.cme
```

## FTP
```bash
for i in $(cat ips.txt) do; crackmapexec ftp $i -u anonymous -p ''  done | tee ftp.cme
```

## SNMP Community Strings
```bash
# Identify hosts with snmp open
sudo nmap -sU -p 161 -iL All_IPS.txt -oG snmp-hosts.nmap -v -Pn -T5 --min-rate 10000 --open

# Modify file for IPs only
cat snmp-hosts.nmap | grep -v "open|filtered" | grep open | cut -d " " -f 2 > snmp-hosts.txt
# note: sometimes the first entry in the file is messed up. manually verify before further continuing


# Write output to file
spool /home/akenofu/snmp-enum.msf
# Mass brute force with metasploit snmp_enum module 
use scanner/snmp/snmp_enum
set rhosts file:/home/akenofu/snmp-hosts.txt
# Show the options to be documented in the spooled output
options
run
# Disable spooling
spool off
```


## SSH
```bash
# TBD
# Automate detection of password based authentication 

# Identify machines with SSH open
sudo nmap -sT -p 22 -iL /home/akenofu/pentest/pentest_IPS -oG ssh-hosts.nmap -v -Pn -T5 --min-rate 10000 --openmv 

nmap -p 1433 --script=ssl-enum-ciphers -iL ips.txt -oN mssql-ssl.txt

# Modify file to correct format
cat ~/pentest/ssh-hosts.nmap  | grep open |cut -d " " -f 2 > ssh-hosts.txt
# note: sometimes the first entry in the file is messed up. manually verify before further continuing

# Using ssh audit
./ssh-audit.py -b -T /home/akenofu/pentest/ssh-hosts.txt | tee /home/akenofu/pentest/port-22.ssh-audit

# using ssh audit json format output
/opt/ssh-audit/ssh-audit.py -b -T  /home/akenofu/pentest/ssh-hosts.txt -jj | tee  /home/akenofu/pentest/port-22.ssh-audit_json


# VScode regex to remove
Starting audit of.+[.]{3}
Running against.+[.]{3}
```

## Port Forward Host port to VMWare
For use with Metasploit and all the modules that deal with reverse shells. These notes assumed VMWare is set up in NAT mode. Bridged mode works, but when multiple NICs are configured for one machine, bridged becomes a pain to deal with.

```batch
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=443 connectaddress=192.168.227.128  connectport=443

:: REM Confirm it works by typing the following on your Linux VM 
curl.exe http://10.32.9.14:443
```

Configure metasploit to listen on local interface while the traffic is proxied from the windows host.

```bash
set LHOST 10.32.10.10
set LPORT 443
set reverselistenerbindaddress 192.168.227.128
set reverselistenerbindport 443
# Not sure if needed
set ReverseAllowProxy false
```