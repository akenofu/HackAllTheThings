# PHP
## Interactive Mode
```bash
php -a
```

## Dump variable
```php
var_dump('0xAAAA' == '43690');
```

## Abuse display_errors=on to leak web root directory
A good example of how to leverage the `display_errors` misconfiguration is by sending a GET request with arrays injected as parameters. This technique, known as Parameter Pollution or Parameter Tampering relies on the fact that most back-end code does not expect arrays as input data. 
```vim
GET /example/index.php?access=&search[]=test&include=all&filter=Filter
HTTP/1.1Host: target
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

---
# PHP Debugging
## PHP
### XDebug and VS Code Remote Debugging
[ Learn How to Debug PHP with Xdebug and VsCode ](https://www.cloudways.com/blog/php-debug/)
[How to install Xdebug and use it in PHP on Ubuntu?](https://linuxhint.com/install-xdebug-and-use-in-php-ubuntu/)