# Methodology
## Decompilers
### [jd-cli ](https://github.com/intoolswetrust/jd-cli)
```bash
./jd-cli --outputDirStructured application application.jar
```

### [jd-gui](https://github.com/java-decompiler/jd-gui)

## Identify Java Process to target
- Using processexplorer, check the working directory of the java application

## Identify Dependencies run by application
- Using processmonitor


## Identify files to target
Java web applications use a deployment descriptor file named `web.xml` to determine how URLs map to servlets,which URLs require authentication, and other information. Within the workingdirectory, we see a `WEB-INFfolder`, which is the Java’s default configuration folder path where we can find the web.xmlfile. This file contains a number of servlet names to servlet classes as well as the servlet name to URL mappings

Checkout the `WEB-INF\lib` folder to identify non-third party libraries and files And libaries shared by EAR files.

EAR files include an `application.xml` file that contains deployment information, which includes the location of external libraries. Let’s check this file, which we can find in the `META-INFdirectory`.  In this file the `<library-directory>APP-INF/lib</library-directory>` XML tag specifies where external libraries are located.

## Identify Starting point
### Handler Functions
we can easily identify the HTTP request handler functions that handle each HTTP request type due to their constant and unique names.These methods are named as follows:
- doGet
- doPost
- doPut
- doDelete
- doCopy
- doOptions

We like to stay as close as possible to the entry points of user input into the application during the beginning stages of our source code audits, searching for all doGetand doPostfunction implementations seems like a good option.

### Handler Functions Parameters

Typically, the doPostand doGetfunctions expect two parameters 
```java
void doGet(HttpServletRequest req,HttpServletResponse resp)
```
first parameter is an HttpServletRequest48object that contains the request a client has made to the web application, and the second one is an HttpServletResponse49object that contains a response the servlet will send tothe client after the request is processed.


### LFI
### GeneralTips
The file class in Java can reference files and directories. Therefore, LFI vulnerabilities enable the attacker to list directories

####  Apache TomEE
```bash
tomcat-users.xml
```

#### HSQLDB
1. Check `crx.properties` to identify if any network ACLs exist
2. Check for connection strings to HSQLDB
```java
jdbc:hsqldb:hsql://127.0.0.1:9001/Application --user sa --password P@ssw0rd123
```

#### General LFI files to look at
1. Batch files, VBS files, PS1 files and other scripts
2. Config files


---
# Java Misc
### Compilete Java File on the fly
```bash
# Compile Java File
javac -source 1.8 -target 1.8 test.java
javac exploit.java

# Convert test.class to test.jar 
mkdir META-INF
echo "Main-Class: test" > META-INF/MANIFEST.MF

# Create Jar file
jar cmvf META-INF/MANIFEST.MF test.jar test.class

# Run file for sanity check
java -jar test.jar

# Run Java file on the fly
javac Exploit.java
java Exploit
```

### Run Java interpreter on the fly
```bash
jshell --class-path /home/akenofu/libs/apache-commons-lang.jar
```




