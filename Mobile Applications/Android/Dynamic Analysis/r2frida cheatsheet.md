### Start the binary with r2frida
```bash
r2 frida://list/usb//
r2 frida://attach/usb//16884
```

### Explore the binary with r2frida
- Retrieve app memory map `\dm~sg.vantagepoint.helloworldjni`
- Retreieve modules `\il`
- In-memory search `\/?`
- in memory search `\/ Hello`
- in memory search with addresses `\dm.@@ hit0_*`
- search for wide version string in-memory `\/w Hello`
- Explore binary info frida `\i`
- Explore module symbols `\is libnative-lib.so`
- Explore modules imports and exports `\ii libnative-lib.so`
- Explore exports `\iE libnative-lib.so`