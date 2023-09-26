### Login system
#### writeup co-written with [bazumo](https://github.com/bazumo)

Challenge source: https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202023/Login%20System
Challenge Author: [maple3142](https://github.com/maple3142)
Category: web

The authentication system used a nim backend. The verification on wether we could access an endpoint was done on the node server, then forwarded the request. Using `Transfer-Encoding: chunkeD`, node would interpret this as a chunked body, while nim would error out, as its`chunked` comparison is case-sensitive. The body for node now becomes a second request. Here is a PoC for accessing /register:

```
POST /login HTTP/1.1
Host: 172.17.0.2:5000
Transfer-Encoding: chunkeD
Connection: keep-alive

a1
POST /register HTTP/1.1
Host: abc
Content-Type: application/json
Content-Length: 71

{"username":"abcheyheX","password":"abcheyheX","privilegeLevel":"user"}
0
```
With that, we could access the /change_password endpoint without admin permissions.

Another bug is that putting a null byte in the username during registration will cause the filename corresponding to it cut before the null byte. Thus, we could create a user name `rce.yaml\u0000`, and it would create a file at /users/rce.yaml.

There is a bug in how nim parses json when it comes to large numbers. This allowed us to have an unescaped string in JSON what we could use to create a YAML payload with javascript code in it. The YAML parser used is an old version known to have this "feature". We added a toString function to priviledgeLevel so that when the template engine wants to render it, it would execute our code and return the flag insted.

```yaml
"privilegeLevel": {"toString": !<tag:yaml.org,2002:js/function> "function (){return global.process.mainModule.constructor._load('child_process').execSync('/readflag').toString()}"}
```

There was also a path traversal in the yaml.load function if we control the session privilege attribute.

With that, we could:
1) register a user named `rce.yaml\u0000`
2) use the change password request smuggling to transform the json user data into a json that has privilegeLevel set to the RCE payload, and comment out the rest of the data as a yaml comment (#)
3) register a user
4) use the change password request smuggling to transform the json privilegeLevel to `../../../users/rce`
5) go to /profile, which will `yaml.load("/server/path/privilegesfolder/../../../users/rce.yaml")` and use toString on the privilegeLevel attribute, giving us the flag
