const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');

test('ramses.decode()', function (t) {
  const payload = {
    key: 'value',
    epd: [{
      aud: ['Audience'],
      alg: "RSA-OEAP",
      ect: "1asdknaslkndaskdnas"
    }]
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.decode(token, options = {
    decrypt: {
      aud: 'Audience',
      key: keys.rsaPublicKey
    }
  }), 'correct decryption data should validate');
  t.throws(function () {
    ramses.decode(token, options = {
      decrypt: {
        key: keys.rsaPublicKey
      }
    });
  });
  t.throws(function () {
    ramses.decode(token, options = {
      decrypt: {
        aud: 'Audience'
      }
    });
  });
  t.end();
});
