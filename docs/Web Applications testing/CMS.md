# CMS
## Tooling cheatsheet
```bash
# The wp-content and force flags may not be needed
wpscan --url <TARGET> -e vp --plugins-detection mixed --api-token  <API_TOKEN> --force --wp-content-dir wp-content

# More aggressive
wpscan --url <TARGET> --rua -e ap,at,tt,cb,dbe,u,m  --passwords /usr/share/seclists/Passwords/probable-v2-top1575.txt  --api-token  <TOKEN> --force --wp-content-dir wp-content
```

