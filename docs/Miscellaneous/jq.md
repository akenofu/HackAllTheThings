# jq

Using jq to query bloodhound data
```bash
# Show keys
cat 20220426210232_users.json | jq '. | keys'

# Go into key
cat 20220426210232_users.json | jq '.data'

# Escape the list ,and go into the properties key of each user
cat 20220426210232_users.json | jq '.data[].Properties'

# Identify users with descriptions
cat 20220426210232_users.json | jq '.data[].Properties | select (.enabled == true) | select (.description != null) | .name + ":" + .description'

# Identify active users that never logged in
# Might be worth bruteforcing; They never reset the default password
# Password set before the user logged in
cat 20220426210232_users.json | jq '.data[].Properties | select (.enabled == true) | select (.pwdlastset > .lastlogontimestamp) | .name + ":" + (.lastlogontimestamp|tostring)'

# Display the OS versions of the computers
cat 20220426210232_computers.json | jq '.data[]Properties | select (.operatingsystem != null ) | .name + ":" + .operatingsystem'

# Identify all computers that have been powered on in the last 2 months
cat 20220426210232_computers.json | jq '.data[]Properties | select (.lastlogontimestamp > 1646237212) | name'
```

Using jq to parse `swagger.json` files
```bash
# Extract GET Endpoints that contain the word Id in one of the parameter inputs
jq '.paths | to_entries | .[] | select(.value.get) | select( .value.get.parameters[].name | test (".*Id") ) | .key' DamnBadlyDesignedAPI_swagger.json 
```