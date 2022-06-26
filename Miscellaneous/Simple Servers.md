### Python
```bash
# HTTP
python -m http.server 80

# FTP
python -m pyftpdlib -p 21 -w -d /tmp

# TFTP
ptftpd -p 69 -v eth0 /tmp

# SMTP
sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25

# SMB
impacket-smbserver -username akenofu -password guest -smb2support share $(pwd) -port 1900
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

### Python3 HTTPS Server
1. Generate certificate
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```
2. Add and the run the following to `serve.py`
```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
                root = os.getcwd()
                if self.path == '/':
                        filename = root + '/index.html'
                else:
                        filename = root + self.path
                f = open(filename, 'rb')
                html = f.read()
                f.close()
                self.wfile.write(html)
                self.send_response(200)
                # self.send_header('Content-type', 'application/javascript')
                self.end_headers

        
                


httpd = HTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket, 
                keyfile="key.pem", 
                        certfile='cert.pem', server_side=True)

httpd.serve_forever()

```

### Python3 HTTPS Server Flask
```python3


```