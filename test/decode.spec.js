const assert = require('assert');
const ramses = require('..');
const keys = require('./keys')
const ALGORITHMS = ramses.ALGORITHMS;

describe('decode', function () {
  var token = ramses.sign({
    param: 'value'
  }, keys.rsaPrivateKey)

  it('invalid token should return null', function () {
    assert.equal(ramses.decode('wrong'), null);
  });

  it('correct key should decrypt encrypted content', function () {
    const payload = {
      key: 'value'
    }
    token = ramses.sign(
      payload, keys.rsaPrivateKey, {
        encrypt: [{
          aud: ['Audience'],
          content: "secret",
          key: keys.rsaPublicKey
        }]
      }
    )
    dtoken = ramses.decode(token, {
      decrypt: {
        aud: 'Audience',
        key: keys.rsaPrivateKey
      }
    });
    assert.equal(dtoken.payload.epd[0].dct, 'secret');
  });

  it('wrong key should not decrypt encrypted content', function () {
    const payload = {
      key: 'value'
    }
    token = ramses.sign(
      payload, keys.rsaPrivateKey, {
        encrypt: [{
          aud: ['Audience'],
          content: "secret",
          key: keys.rsaPublicKey
        }]
      }
    )
    dtoken = ramses.decode(token, {
      decrypt: {
        aud: 'Audience',
        key: keys.rsaWrongPrivateKey
      }
    });
    assert.equal(dtoken.payload.epd[0].dct, undefined);
  });

});
