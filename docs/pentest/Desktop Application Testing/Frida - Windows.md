# Frida Windows
## CLI Options

```bash
# CLI Options
-f : Spanws a process at given path in an paused state
-l : Load an instrumentation script
-s : Include debug symbols
--no-pause : automatically resume after instrumentation is applied
--runtime=qjs : Using QuickJS
--runtime=v8 : Use JavaScript V8 Engine
--pause : Start application paused
```

## CLI

One of the important details of Frida's CLI tools is that parameters are _case sensitive_ in most cases, it is important to take this into consideration. An example is that _lowercase_ parameters are used for functions and _uppercase_ parameters for modules, be it inclusions or exclusions.

Frida-Trace Hooks into a function and generate boiler plate stubs that can be modified for a quick and easy way to hook functions.

```bash
# attach to process by id or name
frida notepad.exe
frida 1234

# Resumes execution inside Frida's REPL
%resume

# Instrument All calls to CreateFileW in all modules
frida-trace -i "CreateFileW" notepad.exe

# Instrument All calls that begin with CreateFile
frida-trace -i "CreateFile*" notepad.exe

# Instruments only `KERNEL32.DLL!CreateFileW`
frida-trace -i "CreateFileW" -I "KERNEL32.DLL" notepad.exe

# Instruments all CreateFileW calls that are not in Kernerl32.dll
frida-trace -i "CreateFileW" -X "KERNEL32.DLL" notepad.exe

# Intrument Function call at specific offset
frida-trace <PID> -a "customLib.DLL!0x1234" notepad.exe

# Instrucment Functions calls with regex
frida-trace -i '*Etw*' notepad.exe

# Run the binary specifying the full path and load the instrumentation script
frida -l .\instrumentation.js -f '.\Reading a WinAPI UTF16 string parameter.exe'
```

## Code Snippets
Frida's enviroment after you execute any of the Frida-CLI tools is usually refered to as Frida's REPL (read–eval–print loop). 
Declare variable without `let`,`const` or `var` inside the REPL.
### Reading a WinAPI UTF16 string parameter 
```js
const searchPathPtr = Module.getExportByName("KERNELBASE.DLL", "SearchPathW");
Interceptor.attach(searchPathPtr, {
    onEnter(args) {
        console.log("Output: " + args[1].readUtf16String())
    }
});
```

### Undoing instrumentation
```js
const redirectString = Memory.allocUtf8String("/bin/foobar");
const statPtr = Module.getExportByName(null, "stat$INODE64");

let statListener = Interceptor.attach(statPtr, {
    onEnter(args) {
        this.removeHook = false;
        let statArg = args[0].readUtf8String(); 
        console.log("stat is checking: " + args[0].readUtf8String());
        if (statArg.indexOf("bin/ls") != -1) {
            args[0] = redirectString;
            this.removeHook = true;
        }

        console.log("final stat path?: " + args[0].readUtf8String());
    },

    onLeave(retval) {
        if (this.removeHook) {
            console.log("Removing stat instrumentation...");
            statListener.detach();
        }
    }
}); 
```

### General-Purpose Snippets
Inside REPL
```js
// Resume execution
%resume

// Enumerate Modules Loaded
Process.enumerateModulesSync()

// Find baseAddress of module, Returns a pointer
myBaseAddr = Module.findBaseAddress('myLib.so');

// Allocate Memory
allocatedMemoryPtr = Memory.allocUtf16String("Some String")

// Read the string, 1024 charchters from string (Can be left empty and frida will auto try and guess where the string ends)
allocatedMemoryPtr.readCString(1024)

// Clear the memory
allocatedMemoryPtr = null

// Overwrite the data at an address with the int value of 12
allocatedMemoryPtr.writeInt(12)

// Allocate empty memory and write to it
t = Memory.alloc(32);
t.writeUtf8String('frida frida rockssssssss')

// Show data in int32 format instead of hexx
Interceptor.attach(addPtr, {
  onEnter(args) {
    console.log("a: " + args[0].toInt32());
  }});


// Read Pointer struct
args[5].readPointer();

// Get base address and add an offset to it
myBaseAddr = Module.findBaseAddress('myLib.so');
myOffsetPtr = myBaseAddr.add(ptr('0x76E'))

// Get pointer to array buffer
myOffsetPtr = myBaseAddr.add(ptr('0x76E'))
test.unwrap()

// HexDump data at address in pretty format
console.log(hexdump(myOffsetPtr))

// To expose a variable in REPL, inside your script add
const CreateFileWPtr = Module.getExportByName('kernelbase.dll', 'CreateFileW')
(global).CreateFileWPtr = CreateFileWPtr


// Call Native function
mkdir = Module.getExportByName(null,'mkdir')
folderName = Memory.allocUtf8String('testingNativeFunctions')
frida_mkdir = new NativeFunction(mkdir,'int',['pointer'])
frida_mkdir(folderName)
```

## Control Scripts
Very useful for RPC exchange of messages between frida and the instrumentation script and child-gating. 

### Simple Control Script
Almost boiler plate code
```python
import os
import sys

import frida

_SCRIPT_FILENAME = 'agent.js'  

def on_message(message, date):
    """Print received messages."""
    print(message)

def main(process_name):
    with open(_SCRIPT_FILENAME, 'r') as script_file:
        code = script_file.read()

    device = frida.get_local_device()
    pid = device.spawn(process_name)
    print('pid: %d' % pid)

    session = device.attach(pid)

    script = session.create_script(code)
    script.on('message', on_message)
    script.load()

    device.resume(pid)

    print('Press CTRL-Z to stop execution.')
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main(sys.argv[1])
```

### Child-gating control script Linux

![](/Screenshots/Pasted%20image%2020221106172409.png)
Boiler plate code from https://raw.githubusercontent.com/frida/frida-python/master/examples/child_gating.py
```python
# -*- coding: utf-8 -*-
from __future__ import print_function

import threading

import frida
from frida_tools.application import Reactor


class Application(object):
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_local_device()
        self._sessions = set()

        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        argv = ["/bin/sh", "-c", "cat /etc/hosts"]
        env = {
            "BADGER": "badger-badger-badger",
            "SNAKE": "mushroom-mushroom",
        }
        print("✔ spawn(argv={})".format(argv))
        pid = self._device.spawn(argv, env=env, stdio='pipe')
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print("[*] attach(pid={})".format(pid))
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        print("[*] enable_child_gating()")
        session.enable_child_gating()
        print("[*] create_script()")
        script = session.create_script("""\
Interceptor.attach(Module.getExportByName(null, 'open'), {
  onEnter(args) {
    send({
      type: 'open',
      path: Memory.readUtf8String(args[0])
    });
  }
});
""")
        script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
        print("[*] load()")
        script.load()
        print("[*] resume(pid={})".format(pid))
        self._device.resume(pid)
        self._sessions.add(session)

    def _on_child_added(self, child):
        print("[+] child_added: {}".format(child))
        self._instrument(child.pid)

    def _on_child_removed(self, child):
        print("[-] child_removed: {}".format(child))

    def _on_output(self, pid, fd, data):
        print("[*] output: pid={}, fd={}, data={}".format(pid, fd, repr(data)))

    def _on_detached(self, pid, session, reason):
        print("[-] detached: pid={}, reason='{}'".format(pid, reason))
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        print("[*] message: pid={}, payload={}".format(pid, message["payload"]))


app = Application()
app.run()
```


# Resources
[Frida basics - Frida HandBook (learnfrida.info)](https://learnfrida.info/basic_usage/)