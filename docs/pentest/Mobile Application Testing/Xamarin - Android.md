# Xamarin

## Reverse Engineering
1. Unpack the apk
```bash
apktool b com.vulnapp.apk
```
2. Inside the unkown assemblies folder use [tools/Xamarin_XALZ_decompress.py at master · x41sec/tools · GitHub](https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py) to parse the headers from XLZ to PE so you can decrypt it with DnSpy


## Traffic Interception
### One technique to rule them all
> AVD does not utilise the built in proxy settings of Android Devices, it utilises some magic under the hood to proxy traffic. **Works on non-proxy aware applications**
1. Set up an Pixel 3a XL android emulated device (needs to have SDK < 29). 
2. Use Android Studio Virtual Device Manager with the following command line args.
3. Drag and drop the APK to the device to install it.
4. Install burp certificate on the device by following the guide: https://secabit.medium.com/how-to-configure-burp-proxy-with-an-android-emulator-31b483237053
```powershell
# -list-avds : List virtual devices
C:\Users\Karim\AppData\Local\Android\Sdk\emulator\emulator.exe -list-avds


# --writeable : start as root
# --http-proxy
C:\Users\Karim\AppData\Local\Android\Sdk\emulator\emulator.exe -avd 'Pixel_3a_XL_API_28'  -http-proxy 127.0.0.1:8080 -writable-system
```

Alternatively, if the device requires Google Play services:
1. Root an Android build with Google Play services using [GitHub - newbit1/rootAVD: Script to root AVDs running with QEMU Emulator from Android Studio](https://github.com/newbit1/rootAVD)
2. Follow the same steps described above, but don't use the `-writable-system` flag when starting the device.

### Intercept Traffic using tooling
- Use [ProxyDroid – Apps on Google Play](https://play.google.com/store/apps/details?id=org.proxydroid&hl=en_GB&gl=US) and Burp NoPE
- [Intercepting Non-HTTP Request Using Burp Suite + Extension (NoPE Proxy) | by #Ujan | Medium](https://medium.com/@juan.tirtayana/intercepting-non-http-request-using-burp-suite-extension-8c264b3c41d1)
### SSL Unpinning
- [GoSecure/frida-xamarin-unpin: A Frida script to bypass Xamarin certificate pinning implementations (github.com)](https://github.com/GoSecure/frida-xamarin-unpin)

## Resources
- [Intercepting Xamarin Mobile App Traffic (triskelelabs.com)](https://www.triskelelabs.com/blog/intercepting-xamarin-mobile-app-traffic-2)
- https://deepsec.net/docs/Slides/2021/Intercepting_Mobile_App_Network_Traffic_aka_%E2%80%9CThe_Squirrel_in_the_Middle%E2%80%9D_Sven_Schleier%20.pdf
- [Invisible proxying - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/proxy/invisible)
- [GitHub - helviojunior/xamarin_sslunpinning](https://github.com/helviojunior/xamarin_sslunpinning)
- [GitHub - GoSecure/frida-xamarin-unpin: A Frida script to bypass Xamarin certificate pinning implementations](https://github.com/GoSecure/frida-xamarin-unpin)
- [How To Capture Non-Proxy Aware Mobile Application Traffic (IOS & Android) Xamarin/Flutter -Pentesting | by salman syed | Medium](https://slmnsd552.medium.com/how-to-capture-non-proxy-aware-mobile-application-traffic-ios-android-xamarin-flutter-924fe044facf)