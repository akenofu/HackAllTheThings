# DotNet Debugging
## Disable Release build optimization
> This is done for better debugging experience

1. In DnSpy click on `Edit Assembly Attributes (C#)`, Now find
```c#
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

2. Replace with
```c#
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

3. Recompile the module
4. Save the module
5. Restart IIS
```batch
iisrestart /noforce
```

## Debug IIS
1. To make sure `w3wp.exe` is running. Browse to any page
2.  Using DnSpy, attach to `w3wp.exe` process
3. Pause execution from debug menu
4. Close all open modules
5. List all modules in DnSpy. `Debug` -> `Windows` -> `Modules`
6. Right click any module and select `Open All Modules`
7. Set breakpoint on interesting functions
8. Resume Execution


# Compile DotNet file on the fly 
```batch
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe C:\Users\Administrator\Desktop\test.cs
C:\Users\Administrator\Desktop\test.cs.exe
```


# Tips and Tricks
- Search the source code for `@Html.Raw(ViewBag.div);` ; Html.Raw renders what it is given without doing any html encoding