# Frida
## Code Snippets
### Patch Register Value at an instruction offset
```js
var targetModule = 'DVIA-v2';
var addr = ptr(0x192c64);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x0 == 0x01){
                    this.context.x0=0x00
                    console.log("Bypass Test1");
            }
        },
    });
```

## Resources
- [Frida-Trace iOS (trelis24.github.io)](https://trelis24.github.io/2019/08/09/Frida-iOS/)
- [Frida Trace (frida-trace) - iOS Pentesting (pentestglobal.com)](https://ios.pentestglobal.com/frida/frida-trace-frida-trace)
- [iOS Hooking With Objection - HackTricks](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting/ios-hooking-with-objection)