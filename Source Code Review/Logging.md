# Database Logging
## MySQL Logging
- Enable Loggin and Replication in `/etc/mysql/my.cnf`
```vim
[mysqld]
...
general_log_file = /var/log/mysql/mysql.log
general_log = 1
```
- Restart MYSQL
```bash
sudo systemctl restart mysql
```
- Check the log file
```bash
sudo tail –f /var/log/mysql/mysql.log
```

or Login as root to MySQL and execute
```sql
SET global general_log_file='/tmp/mysql.log'; 
SET global log_output = 'file';
SET global general_log = on;
```


## PostgreSQL Enable Database Logging
Look for `postgresql.conf` file to edit
```vim
log_statement = 'all' # none, ddl, mod, all
```
 
 ### Windows
 
 Restart the Application to apply the new settings. We can do this by launching `services.msc` from the Runcommand window and finding the Applications  service
 
 Find failed queries in the log file 
 ```batch
 C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\
 ```
 
 ### Linux
 Restart postgresql
```bash
sudo systemctl restart  postgresql
```

Check the logs
```bash
sudo tail -f /var/log/postgresql/postgresql-10-main.log
```


## MariaDB Query Debugging
1. Edit `mysql.log` to enable loggin
```bash
sudo nano /etc/mysql/my.cnf
```

```vim
[mysqld]
...
general_log_file	= /var/log/mysql/mysql.log
general_log		= 1
```

2. Restart mysql 
```bash
sudo systemctl restart mysql
```

3. Tail the log file
```bash
sudo tail -f /var/log/mysql/mysql.log
```


---

# PHP apache2 Logging
## Enable the PHP `display_errors` directive
- Modify `/etc/php5/apache2/php.ini`
- Append the following lines to the file
```vim
display_errors = On
```
- Restart `apache2`
```bash
sudo systemctl restart apache2
```

