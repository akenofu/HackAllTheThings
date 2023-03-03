# Xamarin

## Reverse Engineering
1. Unpack the apk
```bash
apktool b com.vulnapp.apk
```
2. Inside the unkown assemblies folder use [tools/Xamarin_XALZ_decompress.py at master · x41sec/tools · GitHub](https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py) to parse the headers from XLZ to PE so you can decrypt it with DnSpy

## Resources
- [Intercepting Xamarin Mobile App Traffic (triskelelabs.com)](https://www.triskelelabs.com/blog/intercepting-xamarin-mobile-app-traffic-2)
- https://deepsec.net/docs/Slides/2021/Intercepting_Mobile_App_Network_Traffic_aka_%E2%80%9CThe_Squirrel_in_the_Middle%E2%80%9D_Sven_Schleier%20.pdf
- [Invisible proxying - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/proxy/invisible)