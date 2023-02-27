# My host setup
## Virtualization
[Enable Hyper-V on Windows 10 | Microsoft Learn](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v)
[How to Install Hyper-V PowerShell Module (altaro.com)](https://www.altaro.com/hyper-v/install-hyper-v-powershell-module/)
[Convert a VMware VM to Hyper-V in the VMM fabric | Microsoft Learn](https://learn.microsoft.com/en-us/system-center/vmm/vm-convert-vmware?view=sc-vmm-2022#convert-using-the-wizard)
[Run Hyper-V, VirtualBox and VMware on same Computer | Tutorials (tenforums.com)](https://www.tenforums.com/tutorials/139405-run-hyper-v-virtualbox-vmware-same-computer.html)
[How to Convert VMware Image to VirtualBox in Windows (windowsloop.com)](https://windowsloop.com/convert-vmware-to-virtualbox/)
[How to Set Up Hyper-V Nested Virtualization](https://adamtheautomator.com/nested-virtualization/)
[android - USB debugging on physical device within a virtual machine development environment - Stack Overflow](https://stackoverflow.com/questions/60829713/usb-debugging-on-physical-device-within-a-virtual-machine-development-environmen)
[Introducing Microsoft RemoteFX USB Redirection: Part 1 - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-microsoft-remotefx-usb-redirection-part-1/ba-p/247035)

## Fix VMWare copy-paste issue (Windows Host + Parrot Guest)
```bash
sudo vmware-user-suid-wrapper
```

## Grayed out USB Options VMWare
Inside your VM's `.vmx` ,make sure the `usb.restrictions` value is set to true:
```bash
usb.restrictions.defaultAllow = "TRUE"
```
## Disable Side Channels Mitigation VMWare
Inside your VM's `.vmx` file remove the following line:
```bash
ulm.disableMitigations = "TRUE"
```
[matejetz/windows-git-auto-puller: Pulls specified git repositories on Windows (github.com)](https://github.com/matejetz/windows-git-auto-puller)

## Enable Multiple RDP Sessions
[How to Allow Multiple RDP Sessions in Windows 10 and 11? | Windows OS Hub (woshub.com)](https://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10/)