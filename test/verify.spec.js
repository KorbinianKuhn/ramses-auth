const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys')

const payload = {
  'key': 'value'
}

test('ramses.verify()', function (t) {
  const ticket = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.verify(ticket, keys.rsaPublicKey), 'correct key should verify');
  t.notOk(ramses.verify(ticket, keys.rsaWrongPublicKey), 'wrong key should not verify');
  t.end();
});

test('ramses.verify(): alg', function (t) {
  const correctAlgorithm = 'RS256';
  const wrongAlgorithm = 'RS384';

  const ticket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    alg: correctAlgorithm
  });

  t.ok(ramses.verify(ticket, keys.rsaPublicKey, options = {
    alg: correctAlgorithm
  }), 'correct algorithm should verify');
  t.notOk(ramses.verify(ticket, keys.rsaPublicKey, options = {
    alg: wrongAlgorithm
  }), 'wrong algorithm should not verify');
  t.end();
});
