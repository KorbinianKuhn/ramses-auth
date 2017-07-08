# ramses-auth

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
- `options`- Additional options for automated RAMSES features.
    - `alg {string}` - Parameter name for describing the algorithm<br>Default: `RS256`
    - `jti {boolean}` - Add a unique JWT ID (uuidv4).
    - `exp {number}` - Add an expiration time. The value will be added to the current time. 

`alg` must be one a value found in ramses.ALGORITHMS. See above for a table of supported algorithms. If `payload` is not a buffer or a string, it will be coerced into a string using `JSON.stringify`.

Example:

``` js
//Sign a ticket with a unique id and a lifetime of 5 minutes
const exampleTicket = ramses.sign(
    payload: {'key':'value'},
    key: signer.privateKey,
    options: {
        'jti': true,
        'exp': 300
    }
)
```

#### `ramses.verify(ticket, key, algorithm)`
``` js
//Verify exampleTicket and detect algorithm from the jose header
const ticket = ramses.sign(
    ticket: exampleTicket,
    key: signer.publicKey
)
```

#### `ramses.decode(ticket, options)`

#### `ramses.validate(ticket, key, options)`

## Example

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