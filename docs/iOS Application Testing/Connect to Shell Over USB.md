Before running this, make sure the iPhone is connected in VMWare's Removable devices settings. Double check the iPhone trusts the Linux VM. 
From: [SSH Over USB - iPhone Development Wiki](https://iphonedev.wiki/index.php/SSH_Over_USB)
```bash
# on your host
sudo apt-get install usbmuxd-tools
iproxy 2222 22

# if root does not work, try mobile
ssh mobile@127.0.0.1 -p 2222
```