# AWS Cli Cheatsheet
```bash
# List s3 buckets
aws s3 ls

# List s3 bucket content
aws s3 ls s3://website

# Copy files from bucket
aws s3 cp s3://website/index.html /tmp/index.html

# Copy file to bucket
aws s3 cp /tmp/.0xdf s3://website/0xdf.php

# List s3 buckets from localhost
aws --endpoint-url http://10.10.11.113:4566 s3 ls
```