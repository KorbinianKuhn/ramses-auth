# ramses-auth [![Travis](https://img.shields.io/travis/KorbinianKuhn/ramses-auth.svg)](https://travis-ci.org/KorbinianKuhn/ramses-auth/builds)  [![standard](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](http://standardjs.com/)

#### Implementation of RAMSES - Robust Access Model for Securing Exposed Services

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Example](#example)
5. [Testing](#testing)
6. [Contribution](#contribution)
7. [License](#license)

## Introduction

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
- `lifetime {number}` - Lifetime Add an expiration time. The value will be added to the current time.
- `jpi {string}`
    - `type {string}` - Values (root, parent, chain)
    - `parent {Object}` - The parent ticket as JWS.
- `encrypt (Array[Object])` - An array of objects that have to contain the following claims.
    - `aud {Array[string]}` - The audience or audiences that the encryption is meant for.
    - `alg {string}` - The encryption algorithm.
    - `content {Object}` - The content that will be encrypted.
    - `key {Object}` - The public key of the audience defined in the `aud` claim.

`alg` must be one a value found in `ramses.ALGORITHMS`. See above for a table of supported algorithms. If `payload` is not a buffer or a string, it will be coerced into a string using `JSON.stringify`.

Example:

``` js
//Sign a ticket with a unique id and a lifetime of 5 minutes
const exampleTicket = ramses.sign(
    payload: {
        key:'value'
    },
    key: issuer.privateKey,
    options: {
        jti: true,
        lifetime: 300
    }
)

//Sign a ticket with a parent
const childTicket = ramses.sign(
    payload: {
        key:'value'
    },
    key: issuer.privateKey,
    options: {
        jti: true,
        jpi: {
            parent: exampleTicket
        }
    }
)

//Sign a ticket with encrypted content for the audience
const anotherTicket = ramses.sign(
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

#### `ramses.verify(ticket, key, options)`

Verify a JWS ticket. Returns `true` or `false`.

Options:

- `ticket {String}` - The ticket as JWS.
- `key {String}` - The public key of ticket issuer.

`options`

- `alg` - Define the algorithm for a better performance as the verify function does not have to encode the JWS to extract the algorithm from the jose header.

Example:

``` js
//Verify exampleTicket
const ticket = ramses.verify(
    ticket: exampleTicket,
    key: issuer.publicKey
)

//Verify exampleTicket and set algorithm for better performance
const ticket = ramses.verify(
    ticket: exampleTicket,
    key: issuer.publicKey,
    options: {
        alg: 'RS256'
    }
)
```

#### `ramses.decode(ticket, options)`

Return a decoded JWS. The returned object contains `header`, `payload` and `signature`.

Options:

`ticket {String}` - The ticket as JWS.

`options`

- `decrypt {object}` - Automatic decryption of encrypted payload data `epd` if existent and the audience matches.
    - `aud {String}` - The audience that have to be part of `epd`
    - `key {String}` - The private key for decryption.

Example:

``` js
//Decode a ticket
const decodedTicket = ramses.decode(
    ticket: exampleTicket
)

//Decode and automatically decrypt epd content of a ticket
const decodedTicket = ramses.decode(
    ticket: exampleTicket,
    options: {
        decrypt: {
            aud: 'Audience',
            key: audience.privateKey
        }
    }
)
```

#### `ramses.validate(ticket, key, options)`

Validate a ticket. Returns `true` or `false`.

Options:

- `ticket {String}` - The ticket as JWS.
- `key {String}` - The public key of ticket issuer.

`options`

- `aud` - Define the audience that has to exist in the tickets `aud` claim.
- `azp` - Define the authorized party that has to exist in the tickets `azp` claim.

Example:

``` js
//Validate a ticket
let isValud = ramses.validate(
    ticket: exampleTicket,
    key: issuer.publicKey
)

//Validate a ticket and check audience and authorized party
let isValid = ramses.validate(
    ticket: exampleTicket,
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

Copyright (c) 2017 Korbinian Kuhn

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