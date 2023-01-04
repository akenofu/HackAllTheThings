## Add All Kali tools to a vanilla Linux Distro
### Add Kali APT packages to another distro
[How to add Kali Linux repositories to another Linux distribution](https://miloserdov.org/?p=3609)

Note: use the latest Kali source for improved speed.
https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/


**Kali Bleeding Edge has the most updated stable ish tools as it get's the releases from github.**


## Misc Commands for WSL
```powershell
wsl --set-default-version 2

bcdedit /set hypervisorlaunchtype auto

wsl --install -d ubuntu

# Enable Nested Virtualization on host for that VM
Set-VMProcessor -VMName 'Windows 11 dev environment' -ExposeVirtualizationExtensions $true
```
 

## Add Kali Repo

**Tested on WSL Ubuntu, don't upgrade the distro as it breaks everysingle time I tried that**

```bash
# Note: these are the commands I used last time I did this
# Add kali to apt sources list
# Get the latest source list from
# https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/

echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee /etc/apt/sources.list

wget http://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2022.1_all.deb

sudo dpkg -i kali-archive-keyring_2022.1_all.deb

sudo apt-get update -y

```
