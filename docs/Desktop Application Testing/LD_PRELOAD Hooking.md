# Hooking into an ELF binary
## Background information
In Linux, the dynamic linkers are referred to as ld.so and ld-linux.so. The latter is commonly used in contemporary Linux distributions as it handles dynamic linking for executables in the ELF binary format – the current default format on Linux. 
A number of environment variables (envars) can be used during the execution of the dynamic linker, the most important of which (for our purposes) is `LD_PRELOAD`. From the ld.so man page:

`LD_PRELOAD` is… A list of additional, user-specified, ELF shared objects to be loaded before all others.  This feature can be used to selectively override functions in other shared objects.

Essentially, this means that shortly after invocation, the dynamic linker will read the contents of `$LD_PRELOAD` and load any shared objects located at paths defined in the envar before any other (potentially benign) shared objects are loaded. Since it’s easy for a malicious shell script or other executable to set the value of LD_PRELOAD, you can see how this could be leveraged by malware to run additional payloads.


The LD_PRELOAD envar is not the only place where users can specify shared objects to be loaded first. The dynamic linker also consults the file `/etc/ld.so.preload` which can also contain user-specified paths to shared objects. In the case that paths are defined both in the envar and in this file, the envar takes precedence. Additionally, the ld.so.preload file causes a system-wide configuration change, resulting in shared objects being preloaded by any binary on the system.

## A brief note on hooking syscalls and LD_PRELOAD**
Strictly speaking, `fopen` is not the lowest-level you can get for opening files. `open(2)` (and friends) is the syscall everything eventually trickles down to, but we can't intercept the syscall directly it with an `LD_PRELOAD` hook — that's what `ptrace(2)` is for. At most, we could intercept its `libc` wrapper. Nonetheless, hooking `fopen` is enough for demonstration purposes.

## Sample code to hook fopen 

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

typedef FILE *(*fopen_t)(const char *pathname, const char *mode);
fopen_t real_fopen;

FILE *fopen(const char *pathname, const char *mode) {
  fprintf(stderr, "called fopen(%s, %s)\n", pathname, mode);
  return real_fopen(pathname, mode);
}

# Called 
__attribute__((constructor)) static void setup(void) {
  real_fopen = dlsym(RTLD_NEXT, "fopen"); 
  fprintf(stderr, "called setup()\n");
}
```

Compile and run with
```bash
# Compile the Shared Library
gcc -shared -fPIC -ldl preload_test.c -o preload_test.so

# Run the binary with LD_PRELOAD envvar set
LD_PRELOAD=$PWD/preload_test.so ./test
```

## GCC Constructor functions
The way the constructors and destructors work is that the shared object file contains special sections (.ctors and .dtors on ELF) which contain references to the functions marked with the constructor and destructor attributes, respectively. When the library is loaded/unloaded the dynamic loader program (ld.so or somesuch) checks whether such sections exist, and if so, calls the functions referenced therein.

__attribute__((constructor)) is a GCC extension (that's supported by Clang too) which places a pointer to setup in preload_tests .ctors section. The loader then knows to execute the function before anything else (in particular, before main is called). In our setup function, we ask libdl for the next (RTLD_NEXT) resolution of fopen — this should be libc's — and keep a pointer to it. When our test executable runs and opens /etc/hosts, our hooked fopen is caled.



References:
[Correct usage of `LD_PRELOAD` for hooking `libc` functions | Tudor Brindus (tbrindus.ca)](https://tbrindus.ca/correct-ld-preload-hooking-libc/)
[c++ - How exactly does __attribute__((constructor)) work? - Stack Overflow](https://stackoverflow.com/questions/2053029/how-exactly-does-attribute-constructor-work)