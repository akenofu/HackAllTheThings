## Misc
### Compile DotNet file on the fly 
```batch
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe C:\Users\Administrator\Desktop\test.cs
C:\Users\Administrator\Desktop\test.cs.exe
```

### Compilete Java File on the fly
```bash
# Compile Java File
javac -source 1.8 -target 1.8 test.java

# Convert test.class to test.jar 
mkdir META-INF
echo "Main-Class: test" > META-INF/MANIFEST.MF

# Create Jar file
jar cmvf META-INF/MANIFEST.MF test.jar test.class

# Run file for sanity check
java -jar test.jar
```

### Run VBSscripts on the fly
```batch
cscript myscript.vbs
```