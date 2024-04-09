# Extract IPA From AppStore Application
## Manual
> I am using a jailbroken device ,and a Debian VM

```bash
ssh 192.168.114.153

cd /var/containers/Bundle/Application

# Identify Bundle Id
ls * | grep -b 2 <application_name>

cd <bundle_id>

cp -r <application_name>.app Payload/

zip -r /var/root/<application_name>.ipa Payload

cp root@192.168.114.153:/var/root/Chess.ipa .
```

[How to extract iPA from iDevice manually. - Security Workbook on Pentesting (securityboat.in)](https://workbook.securityboat.in/resources/ios-app-pentest/how-to-extract-ipa-from-idevice-manually.)

## Automated
- use [GitHub - AloneMonkey/frida-ios-dump: pull decrypted ipa from jailbreak device](https://github.com/AloneMonkey/frida-ios-dump)