# Xamarin

## Reverse Engineering
1. Unpack the apk
```bash
apktool b com.vulnapp.apk
```
2. Inside the unkown assemblies folder use [tools/Xamarin_XALZ_decompress.py at master · x41sec/tools · GitHub](https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py) to parse the headers from XLZ to PE so you can decrypt it with DnSpy

## Resources
