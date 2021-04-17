### Debug Debuggable Application with JDP
- Execute command in context of app
`run-as com.vulnerable.app id`
- Start debug session with jdb
- Identify PID of last launched process
	`adb jdwp`
- Create Communication channel
	`adb forward tcp:55555 jdwp:16346`
- Start a debug session. for more info check [JDB Tutorial - Tutorialspoint](https://www.tutorialspoint.com/jdb/index.htm)
	`jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555`
	
- Start jdb in suspended state
	```bash
	jdb -attach localhost:7777
	```

***

### Jdb commands
- `classes`: list all loaded classes
- `class/methods/fields class id`: Print details about a class and list its methods and fields
- `locals`: print local variables in current stack frame
- `print/dump expr`: print information about an object
- `stop in method`: set a method breakpoint
- `clear method`: remove a method breakpoint
- `set lvalue = expr`:  assign new value to field/variable/array element
- `suspend`: suspends process
- `resume`: resumes process