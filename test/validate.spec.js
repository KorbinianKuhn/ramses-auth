const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys')

test('ramses.validate(): keys', function (t) {
  const payload = {
    'key': 'value'
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.validate(token, keys.rsaPublicKey), 'correct key should validate');
  t.notOk(ramses.validate(token, keys.rsaWrongPublicKey), 'wrong key should not validate');
  t.end();
});

test('ramses.validate(): algorithm', function (t) {
  const correctAlgorithm = 'RS256';
  const wrongAlgorithm = 'RS384';

  const payload = {
    'key': 'value'
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    alg: correctAlgorithm
  });

  t.ok(ramses.validate(token, keys.rsaPublicKey, options = {
    alg: correctAlgorithm
  }), 'correct algorithm should validate');
  t.notOk(ramses.validate(token, keys.rsaWrongPublicKey, options = {
    alg: wrongAlgorithm
  }), 'wrong algorithm should not validate');
  t.end();
});

test('ramses.validate(): expiration time', function (t) {
  const payload = {
    'key': 'value'
  }
  let token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    lifetime: 300
  });

  t.ok(ramses.validate(token, keys.rsaPublicKey), 'not reached expiration time should validate');

  token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    lifetime: -300
  });

  t.notOk(ramses.validate(token, keys.rsaPublicKey), 'reached expiration time should not validate');
  t.end();
});

test('ramses.validate(): audience', function (t) {
  const payload = {
    'aud': ['CorrectAudience']
  }
  let token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.validate(token, keys.rsaPublicKey, options = {
    aud: 'CorrectAudience'
  }), 'correct audience should validate');

  t.notOk(ramses.validate(token, keys.rsaPublicKey, options = {
    aud: 'WrongAudience'
  }), 'wrong audience should not validate');
  t.end();
});

test('ramses.validate(): authorized party', function (t) {
  const payload = {
    'azp': ['CorrectAuthorizedParty']
  }
  let token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.validate(token, keys.rsaPublicKey, options = {
    azp: 'CorrectAuthorizedParty'
  }), 'correct authorized party should validate');

  t.notOk(ramses.validate(token, keys.rsaPublicKey, options = {
    azp: 'WrongAuthorizedParty'
  }), 'wrong authorized party should not validate');
  t.end();
});

test('ramses.validate(): isValidCallback', function (t) {
  const payload = {
    'key': 'value'
  }
  let token = ramses.sign(payload, keys.rsaPrivateKey);

  function isValidFunction(payload) {
    if (payload.key === 'value') {
      return true;
    } else {
      return false;
    }
  }

  const payload2 = {
    'key': 'wrongValue'
  }
  let token2 = ramses.sign(payload2, keys.rsaPrivateKey);


  t.ok(ramses.validate(token, keys.rsaPublicKey, options = {
    isValidCallback: isValidFunction
  }), "validation callback function should return true and therefore validate");

  t.notOk(ramses.validate(token2, keys.rsaPublicKey, options = {
    isValidCallback: isValidFunction
  }), "validation callback function shoud return false and therefore not validate");

  t.end();
});
