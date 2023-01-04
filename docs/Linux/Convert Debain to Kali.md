## Add All Kali tools to a vanilla Linux Distro
### Add Kali APT packages to another distro
[How to add Kali Linux repositories to another Linux distribution](https://miloserdov.org/?p=3609)

Note: use the latest Kali source for improved speed.
https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/

## Add Kali Repo
```bash
# Note: these are the commands I used last time I did this
# Add kali to apt sources list
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee /etc/apt/sources.list

# Download the kali archive key used to sign the repository
wget 'https://archive.kali.org/archive-key.asc' --no-check-certificate

# Add it to list of trusted apt keys
sudo apt-key add archive-key.asc
```

### Install Kali tools
```bashsudo apt install kali-linux-large -y
sudo apt-get update

sudo apt install kali-linux-core
```