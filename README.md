# safe-inject

[![Build Status](https://travis-ci.org/pori/safe-exec.svg?branch=master)](https://travis-ci.org/pori/safe-exec)
[![NPM version][npm-image]][npm-url]

Controlled remote code execution. Great for debugging on a live server. Extremely dangerous for everything else.

Uses RSA key pairs.

# Installation

```sh
npm install safe-exec
```

# Example

Visit page with very some specific query parameters:

* `publicKey` - plain text passphrase. _WARNING: Persisted in session._
* `message` - _optional_ value of any kind.

```
example.com?privateKey=foobar&message=evil.js
```

Then somewhere in your bundle js:

```js
exec(location.search, 'reallylongcipher', sessionStorage, (message) => {
  let victim = document.querySelector('script[src="foobar.js"]');

  victim.setAttribute('src', message);
});
```

# FAQ

## _Wow this is great idea! Should I use this in production?_

You should *never* use this in a production environment. This library creates an intentional backdoor for your front-end, which is a huge security risk.

## _Why would you intentionally build a backdoor?_

This is useful for environments that are difficult replicate on your local machine. It helps to speed up development and debugging.

# API

## exec(search, publicKey, sessionStorage, cb)

Executes code if a public/private key pair is present.

* `search` - should just be `window.location.search`.
* `publicKey` - any valid RSA public key.
* `sessionStorage` - pass a reference to DOM `sessionStorage` to persist execution across session.
* `cb` - callback `message => ` where code execution is defined.

# License

MIT

---

> [pori.io](http://pori.io) &nbsp;&middot;&nbsp;
> GitHub [@pori](https://github.com/pori) &nbsp;&middot;&nbsp;
> Twitter [@pori_alex](https://twitter.com/pori_alex)
