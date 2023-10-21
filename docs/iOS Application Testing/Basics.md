# Basics
```bash
# SSH to device
# mobile user password is set when you first install Sileo
ssh mobile@192.168.178.94 

# Transfer files from Phone to desktop
scp root@localhost:/tmp/hi.txt .

# List installed applications
ideviceinstaller -l

# Sign iOS application
cd /var/containers/Bundle/Application
# Identify Bundle Id for the app, in my case the app name is dvia
ls | grep diva -i -B 2
cd F6CB934B-C989-4FB3-BD08-58F339BEF448
ldid -S DVIA-v2.app
```
## Install Fake IPAs
Refer to: [Setting Up iPhone 8 — iOS 16.2— for testing: palera1n, Sileo, Burp, Frida, Objection ,and more [2023] (akenofu.me)](https://blog.akenofu.me/setting-up-iphone-8-ios-16-for-pen-testing-ios-apps-2023/)
1. Inside, Sileo add `https://cydia.akemi.ai/` as source.
2. From the new packages install appinst and appsync Unified
3. Inside an SSH shell `appinst /var/root/<application_name>.ipa`

**Alternatively,**
- Use [Sideloadly - iOS & Apple Silicon Sideloading](https://sideloadly.io/)

Alternatively,
- Download TrollStore helper using Sileo
- Use TrollStore to intall the app
From: [An bug in the ElleKit code injection framework causes AppSync Unified to not work correctly on some jailbreak environments (※ Dopamine, palera1n-c in `-l` rootless mode, etc.) in certain configurations · Issue #174 · akemin-dayo/AppSync · GitHub](https://github.com/akemin-dayo/AppSync/issues/174)

## Get Device UDID
1.  Open up the latest version of [**iTunes**](http://www.apple.com/itunes/) and **connect your iOS device to your computer.**
2.  **Select your iOS device** by clicking the device’s image located at the upper-left corner of iTunes’s UI.
3. On the next screen, a window should appear listing your phone’s Capacity, Phone Number, and Serial Number.
4. By clicking on **Serial Number** once, the prompt should change to display your **UDID**.
	![](/Screenshots/Pasted%20image%2020230113102610.png)

## Signed ipsws
- [Download iOS Firmware for iPhone, iPad, iPod Touch, Apple Watch, Apple TV and HomePod / IPSW Downloads](https://ipsw.me/)

## Restart the SpringBoard from SSH
```bash
ssh root@192.168.114.153

killall -9 SpringBoard

# Not always needed, test the previous command first
reboot
```

## Install Old Versions of iOS App
- [AppStore++ Download for iOS (onejailbreak.com)](https://onejailbreak.com/blog/appstoreplusplus/)

