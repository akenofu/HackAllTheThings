- These notes are gathered from our field pentests. It contains scripts to automate mass vulnerability scanning of some of the low hanging fruit we find around in massive networks.

### SNMP Community Strings
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


### Weak Encryptian Ciphers
```bash
# Identify machines with SSH open
sudo nmap -sT -p 22 -iL /home/akenofu/ebe/EBE_IPS -oG ssh-hosts.nmap -v -Pn -T5 --min-rate 10000 --openmv 


# Modify file to correct format
cat ~/ebe/ssh-hosts.nmap  | grep open |cut -d " " -f 2 > ssh-hosts.txt
# note: sometimes the first entry in the file is messed up. manually verify before further continuing

# Using ssh audit
./ssh-audit.py -b -T /home/akenofu/ebe/ssh-hosts.txt | tee /home/akenofu/ebe/port-22.ssh-audit

# using ssh audit json format output
/opt/ssh-audit/ssh-audit.py -b -T  /home/akenofu/ebe/ssh-hosts.txt -jj | tee  /home/akenofu/ebe/port-22.ssh-audit_json


# VScode regex to remove
Starting audit of.+[.]{3}
Running against.+[.]{3}


```
