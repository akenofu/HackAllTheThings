## Configure PC to use kerberos Ticket
```bash
# 1. Modify Realm
vim /etc/krb5.conf

# 2. Sync time with server using NTP
date; sudo nptdate 10.91.10.10; date

# 3. Create ticket from user and password
kinit k.john
```


## Misc

```bash
# Find Time difference between PC and server
ntpdate -q 10.91.10.10

# List Active Kerberos Tickets
klist

# List tickets in keytab file
klist -kt /etc/krb5.keytab 

# Swith to super user kerberos
Kadmin -kt /etc/krb5.keytab -p kadmin/admin@realcorp.hgb -q "add_principal" -pw password root@realcorp.htb
```

## Modify Kerberos Database
```bash
# list principles using account from keytab file
kadmin -kt /etc/krb5.keytab -p kadmin/admin@realcorp.hgb -q "list_principals"

# Add principal using account from keytab file
Kadmin -kt /etc/krb5.keytab -p kadmin/admin@realcorp.hgb -q "add_principal" admin/admin@realcorp.htb

```
