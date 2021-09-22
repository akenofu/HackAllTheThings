### Python
```bash
# HTTP
python -m http.server 80

# FTP
python -m pyftpdlib -p 21 -w -d /tmp

# TFTP
ptftpd -p 69 -v eth0 /tmp

# SMTP
python -m smptd -n -c DebuggingServer 10.10.14.2:25

# SMB
impacket-smbserver -username akenofu -password guest -smb2support share $(pwd)


```

> Authenticate to Impacket SMB server from windows machine with creds
```batch
# Run as netonly to authenticate to smb share with different creds from powershell
runas /user:akenofu /netonly
```

### Spin Quick containerized  Webserver in a VPS
```bash
# Setup HTTP server
python -m http.server 8080

# Use ngrok to forward connections
ngrok http 8000
```

### PHP Server
```bash
php -S 0.0.0.0:80
```