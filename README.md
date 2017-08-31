# ramses-auth [![Travis](https://img.shields.io/travis/KorbinianKuhn/ramses-auth.svg)](https://travis-ci.org/KorbinianKuhn/ramses-auth/builds)  [![standard](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](http://standardjs.com/)

#### Implementation of RAMSES - Robust Access Model for Securing Exposed Services

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Testing](#testing)
5. [Contribution](#contribution)
6. [License](#license)

## Introduction

RAMSES is an easily adoptable, customizable and
robust security model which will not consider any trusted
zones. It proposes an authentication and authorization pattern
for inter-service communication utilizing and extending JSON
Web Signatures (JWS) as tickets. RAMSES includes various
extensions for individual security levels and requirements, like
access capabilities, ticket invalidation, usage limitation and
payload encryption.

A detailed explanation of RAMSES will follow.

## Installation

For installation use the [Node Package Manager](https://github.com/npm/npm):

```
$ npm install --save ramses-auth
```

or clone the repository:
```
$ git clone https://github.com/KorbinianKuhn/ramses-auth
```

## Usage

#### `ramses.sign(payload, key, options)`

Return a JSON Web Signature.

Options:

- `payload {Object}` - The payload data for the jws.
- `key {Object}` - Private key to sign the jws.

`options`

- `alg {string}` - Parameter name for describing the algorithm<br>Default: `RS256`
- `jti {boolean}` - Add a unique JWT ID (uuidv4).
- `ttl {number}` - time to live / lifetime of the token. The value will be added to the current time and stored as expiration time under the `exp` claim.
- `jpi {string}`
    - `type {string}` - Values (root, parent, chain).
    - `parent {Object}` - The parent token as JWS.
- `encrypt (Array[Object])` - An array of objects that have to contain the following claims:
    - `aud {Array[string]}` - The audience or audiences that the encryption is meant for.
    - `alg {string}` - The encryption algorithm.
    - `content {Object}` - The content that will be encrypted.
    - `key {Object}` - The public key of the audience defined in the `aud` claim.

`alg` must be one a value found in `ramses.ALGORITHMS`. If `payload` is not a buffer or a string, it will be coerced into a string using `JSON.stringify`.

Example:

``` js
//Sign a token with a unique id and a lifetime of 5 minutes
const token = ramses.sign(
    payload: {
        key:'value'
    },
    key: issuer.privateKey,
    options: {
        jti: true,
        ttl: 300
    }
)

//Sign a token with a parent
const tokenWithParent = ramses.sign(
    payload: {
        key:'value'
    },
    key: issuer.privateKey,
    options: {
        jti: true,
        jpi: {
            parent: token
        }
    }
)

//Sign a token with encrypted content for the audience
const token = ramses.sign(
    payload: {
        aud: ['Audience']
    },
    key: issuer.privateKey,
    options: {
        encrypt: [
            {
                aud: ['Audience'],
                key: audience.publicKey,
                content: {
                    secret: 'value'
                }
            }
        ]
    }
)
```

#### `ramses.verify(token, key, options)`

Verify a JWS token. Returns `true` or `false`.

Options:

- `token {String}` - The token as JWS.
- `key {String}` - The public key of token issuer.

`options`

- `alg` - Define the algorithm for a better performance as the verify function does not have to encode the JWS to extract the algorithm from the jose header.

Example:

``` js
//Verify token
const valid = ramses.verify(
    token: token,
    key: issuer.publicKey
)

//Verify token and set algorithm for better performance
const valid = ramses.verify(
    token: token,
    key: issuer.publicKey,
    options: {
        alg: 'RS256'
    }
)
```

#### `ramses.decode(token, options)`

Return a decoded JWS. The returned object contains `header`, `payload` and `signature`.

Options:

`token {String}` - The token as JWS.

`options`

- `decrypt {object}` - Automatic decryption of encrypted payload data `epd` if existent and the audience matches.
    - `aud {String}` - The audience that has to be part of `epd` claim.
    - `key {String}` - The private key for decryption.

Example:

``` js
//Decode a token
const dtoken = ramses.decode(
    token: token
)

//Decode and automatically decrypt epd content of a token
const dtoken = ramses.decode(
    token: token,
    options: {
        decrypt: {
            aud: 'Audience',
            key: audience.privateKey
        }
    }
)
```

#### `ramses.validate(token, key, options)`

Validate a token. Returns `true` or `false`.

Options:

- `token {String}` - The token as JWS.
- `key {String}` - The public key of token issuer.

`options`

- `aud` - Define the audience that has to exist in the tokens `aud` claim.
- `azp` - Define the authorized party that has to exist in the tokens `azp` claim.
- `isValidCallback {function}` - Add a custom function that will be executed for validation. The function receives the payload of the decoded token as an argument.

Example:

``` js
//Validate a token
let isValid = ramses.validate(
    token: token,
    key: issuer.publicKey
)

//Validate a token and check audience and authorized party
let isValid = ramses.validate(
    token: token,
    key: issuer.publicKey,
    options: {
        aud: 'Audience',
        azp: 'Authorized Party'
    }
)
```

## Testing

First you have to install all dependencies:

```
$ npm install
```

To execute all unit tests once, use:

```
$ npm test
```

or to run tests based on file watcher, use:

```
$ npm start
```

To get information about the test coverage, use:

```
$ npm run coverage
```

## Contribution
Fork this repository and push in your ideas.

Do not forget to add corresponding tests to keep up 100% test coverage.

## License
The MIT License

Copyright (c) 2017 Korbinian Kuhn, Tobias Eberle, Christof Kost, Steffen Mauser, Marc Schelling

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.