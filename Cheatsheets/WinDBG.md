### Configure Symbols
#### For Developer Created Binaries
- Place PDB file where image itself is (VS does this by default)
- or place in a repo and point debugger to it
	- Goto Settings -> Debugging Settings
	- Add your symbols to Symbol Paths preceded by `;`
#### For WIndows Binaries
- Connect to Microsoft Symbol Server using the `_NT_SYMBOL_PATH` enviroment variable
- Set `_NT_SYMBOL_PATH` to `srv*c:\symbols*https://msdl.microsoft.com/download/symbols`
#### Force Reload Symbols
```bash
.reload /f user32.dll
```

***

## Commands
```bash
# list loaded modules
lm

# List threads in process
~

# Convert Hex to Decimal
? 1ab4

# Convert Decimal to Hex
? 0n6836

# Examine TEB, What windows thinks is most important
!teb 00000066`f1dac000

# Examie struct definition 
dt _teb 

# Examine struct definition with module followed by structure name
dt ntdll!_teb



```


