const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys')

const payload = {
  'key': 'value'
}

test('ramses.verify()', function (t) {
  t.notOk(ramses.verify('wrong', keys.rsaPublicKey), 'wrong token should not verify');

  const token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.verify(token, keys.rsaPublicKey), 'correct key should verify');
  t.notOk(ramses.verify(token, keys.rsaWrongPublicKey), 'wrong key should not verify');
  t.end();
});

test('ramses.verify(): alg', function (t) {
  const correctAlgorithm = 'RS256';
  const wrongAlgorithm = 'RS384';

  const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    alg: correctAlgorithm
  });

  t.ok(ramses.verify(token, keys.rsaPublicKey, options = {
    alg: correctAlgorithm
  }), 'correct algorithm should verify');
  t.notOk(ramses.verify(token, keys.rsaPublicKey, options = {
    alg: wrongAlgorithm
  }), 'wrong algorithm should not verify');
  t.end();
});
