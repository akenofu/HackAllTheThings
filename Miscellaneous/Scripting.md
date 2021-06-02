# Scripting
## Python
### Proxy all HTTP(S) traffic
Set the `http_proxy` enviroment variable from bash/powershell or append the following lines to beginning of the python script

```python
import os

proxy = 'http://<user>:<pass>@<proxy>:<port>'

os.environ['http_proxy'] = proxy 
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

#your code goes here.............
```

### Enter Debbuger After script execution
```python
# some code here

import pdb; pdb. set_trace()
```

