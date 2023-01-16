# Objection
## Code Snippets
```bash
objection --gadget DVIA-v2 explore

# Bypass JB detection
ios jailbreak disable 

# Find classes with name
ios hooking search classes jailbreak

# Find class methods
ios hooking watch class JailbreakDetection

# Dump ret value of isJailbroken method invocation from JailbreakDetection class
ios hooking watch method "+[JailbreakDetection isJailbroken]" --dump-return --dump-args

# Hook isJailbroken and replace ret value
ios hooking set return_value '+[JailbreakDetection isJailbroken]' 0x0
```