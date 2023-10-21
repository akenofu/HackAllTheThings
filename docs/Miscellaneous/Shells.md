# Interactive Shells
## Linux

#### Spawn TTY

```bash
# Any of the following 3 spawns a tty
script -q /dev/null 
script /dev/null -c bash
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Fixes terminal
export TERM=xterm
```

#### Recieve Shell
```bash
rlwrap nc -nlvp 8900
```


## Windows
[ConPtyShell is a Fully Interactive Reverse Shell for Windows systems.](https://github.com/antonioCoco/ConPtyShell)

# Shell Generators
[Reverse Shell Generator](https://www.revshells.com/)
