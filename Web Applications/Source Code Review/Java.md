## Identify Java Process to target
- Using processexplorer, check the working directory of the java application

## Identify Dependencies run by application
- Using processmonitor

## Identify files to target
Java web applications use a deployment descriptor file named `web.xml` to determine how URLs map to servlets,which URLs require authentication, and other information. Within the workingdirectory, we see a `WEB-INFfolder`, which is the Java’s default configuration folder path where we can find the web.xmlfile. This file contains a number of servlet names to servlet classes as well as the servlet name to URL mappings

Checkout the `WEB-INF\lib` folder to identify non-third party libraries and files.

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