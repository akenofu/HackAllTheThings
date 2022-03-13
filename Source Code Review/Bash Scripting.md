## Grep cheatsheet
```bash
# with colors and recursive
grep -r "function AddAttachment" --color 2>/dev/null /usr/local/mywebapp/
```

## Examine File structure
```bash
tree -L 3 .
```

## Unzip Ear Files
```bash
unzip -q  application.ear -d application
```

## Get MiliSeconds since EPOCH
```bash
# includes 3 digits of miliseconds
date +%s%3N
```

## Apache2
```bash
# Enable
sudo systemctl start apache2

# Tail the logs
sudo tail -f /var/log/apache2/access.log
```

## Base64 Powershell payload
```bash
iconv -f ASCII -t UTF-16LE shell.ps1 | base64 | tr -d "\n"
```

## Search for uploaded file in file system
```bash
sudo find / -name "poc.txt"
```

## Find writable directories
```bash
sudo find /var/www/html/ -type d -perm -o+w
```

## Find top 10000 lines in file using jq
```bash
jq '.[0:10000]' names.json 
```

## Download all files in list file using wget
```bash
wget --no-check-certificate -i custom_js.txt
```

## Beautify JS files 
Uses Python3 jsbeautifier 

1. Install python3-jsbeautifier
```bash
sudo pip3 install jsbeautifier
```
2. 
```bash
for f in *.js; do js-beautify $f > pretty/"${f}"; done;
```