# Reversing iOS Apps
## Ghidra
1. unzip the IPA file
```bash
unzip DVIA-v2.ipa
```
2. Fire up Ghidra and open the `Payload/DVIA-v2.app/DVIA-v2` file

## Check for Symbols
In a Linux terminal,
```bash
llvm-objdump --syms Payload/DVIA-v2.app/DVIA-v2
```

## ARM64 Resources
[A Guide to ARM64 / AArch64 Assembly on Linux with Shellcodes and Cryptography | modexp (wordpress.com)](https://modexp.wordpress.com/2018/10/30/arm64-assembly/)


## Resources
- [debugging - What's the dSYM and how to use it? (iOS SDK) - Stack Overflow](https://stackoverflow.com/questions/3656391/whats-the-dsym-and-how-to-use-it-ios-sdk)
- [ios - Should I use 'Strip Debug Symbols During Copy' and 'Strip Linked Produts' with Google Analytics? - Stack Overflow](https://stackoverflow.com/questions/15125816/should-i-use-strip-debug-symbols-during-copy-and-strip-linked-produts-with-g)