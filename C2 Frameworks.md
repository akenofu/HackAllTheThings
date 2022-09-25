# Empire 4.0
## Installation
1. Install python3.9 as recommended by bc-security

via apt
```bash
sudo apt install python3.9 python3.9-dev
```

Alternatively,

```bash
cd /tmp
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev
wget https://www.python.org/ftp/python/3.9.1/Python-3.9.1.tgz
tar -xf Python-3.9.1.tgz
cd Python-3.9.1
sudo ./configure --enable-optimizations
sudo make install
```

2. Install poetry for python3.9
```bash
pip3.9 install poetry
```

3. Install empire

```bash
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
poetry env use $(which python3.9)
setup/install.sh
```

4. Download a compiled starkiller binary from
https://github.com/BC-SECURITY/Starkiller/releases/tag/v1.10.0

Reference
https://bc-security.gitbook.io/empire-wiki/quickstart/installation

## Start Empire
1. Start empire team server with custom username and password
```bash
 ./ps-empire server --username <user_name> --password <password>
```

2. Fireup start killer and login

