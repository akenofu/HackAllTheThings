# HSQLDB
### Connect to HSQLDB
```java
java -cp hsqldb.jar org.hsqldb.util.DatabaseManagerSwing --url jdbc:hsqldb:hsql://opencrx:9001/CRX --user sa --password manager99

// Or
java -jar hsqldb-2.6.0-jdk11.jar
```
### Java Language Routines
 Use a function if the java method returns a variable. Otherwise, if the java method returns void use procedures.
 #### Create Function
```sql
CREATE FUNCTION systemprop(IN key VARCHAR) RETURNS VARCHAR 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:java.lang.System.getProperty'
```
#### Use Function
```sql
VALUES(systemprob('java.class.path'))
```

#### Create WriteBytesToFile Function
```sql
CREATE PROCEDURE writeBytesToFilename(IN paramString VARCHAR, IN paramArrayOfByte VARBINARY(1024)) 
LANGUAGE JAVA 
DETERMINISTIC NO SQL
EXTERNAL NAME 'CLASSPATH:com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename'
```

#### Call WriteBytesToFile Function
```sql
call writeBytesToFilename('test.txt', cast('497420776f726b656421' AS VARBINARY(1024))
```