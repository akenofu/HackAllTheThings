# Configure WinDBG
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
#### Enable dml
```bash
.prefer_dml 1
```

***
# Commands
## Threads
```bash
# list loaded modules
lm

# List threads in process
~

# Convert Hex to Decimal
? 1ab4

# Convert Decimal to Hex
? 0n6836

# Examine current active thread TEB
!teb

# Examine TEB, What windows thinks is most important
!teb 00000066`f1dac000

# Examie struct definition 
dt _teb 

# Examine struct definition with module followed by structure name
dt ntdll!_teb


# Examine Teb Values 
dt ntdll!_teb 00000070`b46ed000

# switch to different thread, thread 0
~0s

# Examine PEB
!peb

# Exame PEB using DT
dt ntdll!_peb 00000070b46ea000
```
## Stacks
```bash
# Print Call stack
k

# Print thread 2 Call stack
~2k
```

## Breakpoints
```bash
# Set break point at symbol
bp kernel32!createfilew

# List breakpoint
bl

# disable breakpoint
bd0

# clear breakpoint
bc0

# continue execution
g

# examine rcx register
r rcx

# change rcx register value
r rcx=00000000000c033e

# Display with the format of byte
db 00000000000c033e

# display with the format of Unicode
du 0000029f864d84f0

# display with the format of Unicode from register directly
du @rcx

# display with double word format[4 bytes] starting this address
dd 000000b5`6092ea88+28

# display with double word format[4 bytes] starting this address with range 1
dd 000000b5`6092ea88+28 L1
```