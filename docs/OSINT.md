# OSINT
## Asset Discovery & Reconnaissance
### Techniques
- Scrap Stackoverflow posts for secerets:
	[ Stack Exchange Data Dump ](https://archive.org/details/stackexchange)
	[Baking Flask cookies with your secrets](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)
- Search the internet: Google, Shodan, GitHub, APIs.Guru and ProgrammableWeb
- Google Dorking
	[Google Hacking Database (GHDB) - Google Dorks, OSINT, Recon (exploit-db.com)](https://www.exploit-db.com/google-hacking-database)
- Search GitHub:
	- API Keys
	- Pull Requests
	- Issues
- Fingerprint TLS using JARM 
	- [JARM: A Solid Fingerprinting Tool for Detecting Malicious Servers ](https://securitytrails.com/blog/jarm-fingerprinting-tool)
	- [D2 COMMSEC - JARM Randomizer Evading JARM Fingerprinting](https://conference.hitb.org/hitbsecconf2021ams/materials/D2%20COMMSEC%20-%20JARM%20Randomizer%20Evading%20JARM%20Fingerprinting%20-%20Dagmawi%20Mulugeta.pdf)
- [Identify Domains registered by a person](https://www.labnol.org/internet/find-websites-of-someone/20550/)
	- Reverse Whois Lookups with Google
	- Perform Reverse IP Lookups
	- Reverse Google AdSense Lookups
	- Reverse Google Analytics Lookups
	- Reverse Google tag lookup

### WebApps

- [OSINT.SH - All in one Information Gathering Tools](https://osint.sh/)
- [Search for a list of websites by content inside their HTML such as: google tag ID, ad sense ID, etc. - NerdyData]([Search for a list of G-LJTF7R1QRG websites - NerdyData](https://www.nerdydata.com/reports/new?search={%22all%22:[{%22type%22:%22code%22,%22value%22:%22G-LJTF7R1QRG%22}],%22any%22:[],%22none%22:[]}))
- [DNSdumpster.com - dns recon and research, find and lookup dns records](https://dnsdumpster.com/)

### Tools

- [six2dez/reconftw: reconFTW is a tool designed to perform automated recon on a target domain ](https://github.com/six2dez/reconftw)
- [yogeshojha/rengine: reNgine is an automated reconnaissance framework for web applications ](https://github.com/yogeshojha/rengine)
- [OWASP/Amass: In-depth Attack Surface Mapping and Asset Discovery (github.com)](https://github.com/OWASP/Amass)
- [darkoperator/dnsrecon: DNS Enumeration Script (github.com)](https://github.com/darkoperator/dnsrecon)
- [pry0cc/axiom:Distribute the workload of many different scanning tools with ease, including nmap, ffuf, masscan, nuclei, meg and many more! (github.com)](https://github.com/pry0cc/axiom)

### Cheatsheet
```bash
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns

# Follow the installation instructions in the reconftw wiki to build the image
# -p	Passive - Perform only passive steps
# -n	OSINT - Performs an OSINT scan (no subdomain enumeration and attacks)
# -s	Subdomains - Perform only subdomain enumeration, web probing, subdomain takeovers
sudo docker run -it --rm  -v "${PWD}/reconftw.cfg":'/reconftw/reconftw.cfg'  -v "${PWD}/Recon/":'/reconftw/Recon/' <IMAGE_ID> -l /reconftw/Recon/domains.txt -spn -o /reconftw/Recon/output


python3 cloud_enum.py -k <key_word> -t 10 

python3.11 theHarvester.py -d <DOMAIN> -b all
```