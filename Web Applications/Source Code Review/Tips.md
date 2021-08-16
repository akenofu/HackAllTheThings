- If possible, always enable database query logging
- Use debug print statements in interpreted code
- Attempt to live-debug the target compiled application (dnSpymakes this relatively easy for .NET applications. The same can be achieved in the Eclipse IDE for Java applications although with a bit more effort)
- After checking unauthenticated areas, focus on areas of the application that are likely to receive less attention (i.e., authenticated portions of the application)
- Investigate how sanitization of user input is performed. Is it done using a trusted, open-source library, or is a custom solution in place?


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


## Dump PHP Variables
- Create new file `dump.php`
```php
<?php var_dump(get_magic_quotes_gpc());?>
```
- Curl the output of that file
```bash
curl http://localhost/dump.php
```