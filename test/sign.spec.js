const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys')

const ALGORITHMS = ramses.ALGORITHMS;

test('ramses.sign()', function (t) {
  const payload = {
    "key": "value"
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.decode(token), 'correct key should decode');
  t.ok(ramses.verify(token, keys.rsaPublicKey), 'correct key should verify');
  t.end();
});

ALGORITHMS.forEach(function (alg) {
  test('ramses.sign(): algorithm ' + alg, function (t) {
    const payload = {
      "key": "value"
    }
    const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
      alg: alg
    });

    t.ok(ramses.verify(token, keys.rsaPublicKey, algorithm = alg)), 'should verify';
    t.throws(function () {
      ramses.sign(payload, keys.rsaPrivateKey, options = {
        alg: 'invalidAlgorithm'
      });
    });
    t.end();
  });
});

test('ramses.sign(): jti', function (t) {
  const payload = {
    "key": "value"
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true
  });

  const dtoken = ramses.decode(token);
  t.ok(('jti' in dtoken.payload), 'jti should exist in payload');

  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  t.ok(dtoken.payload.jti.match(uuidPattern), 'jti should match uuid pattern');

  t.end();
});

test('ramses.sign(): lifetime', function (t) {
  const payload = {
    "key": "value"
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    lifetime: 300
  });

  const dtoken = ramses.decode(token);

  t.ok(('exp' in dtoken.payload), 'exp should exist in payload');

  t.end();
});

test('ramses.sign(): jpi', function (t) {
  const payload = {
    "key": "value"
  }
  const tokenRoot = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {}
  });
  const tokenChildA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      parent: tokenRoot
    }
  });
  const tokenChildB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      parent: tokenChildA
    }
  });

  const dtokenRoot = ramses.decode(tokenRoot);
  const dtokenChildA = ramses.decode(tokenChildA);
  const dtokenChildB = ramses.decode(tokenChildB);

  t.ok((dtokenRoot.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((dtokenChildA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((dtokenChildB.payload.jpi.length == 2), 'length of jpi array of childB ticket should be 2');

  t.ok((dtokenChildA.payload.jpi[0] === dtokenRoot.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((dtokenChildB.payload.jpi[0] === dtokenRoot.payload.jti && dtokenChildB.payload.jpi[1] === dtokenChildA.payload.jti), 'uuids of jpi of childB shoud be uuid of root ticket and childA ticket');

  t.end();
});

test('ramses.sign(): jpi, type=root', function (t) {
  const payload = {
    "key": "value"
  }
  const tokenRoot = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root'
    }
  });
  const tokenChildA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root',
      parent: tokenRoot
    }
  });
  const tokenChildB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root',
      parent: tokenChildA
    }
  });

  const dtokenRoot = ramses.decode(tokenRoot);
  const dtokenChildA = ramses.decode(tokenChildA);
  const dtokenChildB = ramses.decode(tokenChildB);

  t.ok((dtokenRoot.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((dtokenChildA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((dtokenChildB.payload.jpi.length == 1), 'length of jpi array of childB ticket should be 1');

  t.ok((dtokenChildA.payload.jpi[0] === dtokenRoot.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((dtokenChildB.payload.jpi[0] === dtokenRoot.payload.jti), 'uuid of jpi of childB shoud be uuid of root ticket');

  t.end();
});

test('ramses.sign(): jpi, type=parent', function (t) {
  const payload = {
    "key": "value"
  }
  const tokenRoot = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent'
    }
  });
  const tokenChildA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent',
      parent: tokenRoot
    }
  });
  const tokenChildB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent',
      parent: tokenChildA
    }
  });

  const dtokenRoot = ramses.decode(tokenRoot);
  const dtokenChildA = ramses.decode(tokenChildA);
  const dtokenChildB = ramses.decode(tokenChildB);

  t.ok((dtokenRoot.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((dtokenChildA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((dtokenChildB.payload.jpi.length == 1), 'length of jpi array of childB ticket should be 1');

  t.ok((dtokenChildA.payload.jpi[0] === dtokenRoot.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((dtokenChildB.payload.jpi[0] === dtokenChildA.payload.jti), 'uuid of jpi of childB shoud be uuid of childA ticket');

  t.end();
});

test('ramses.sign(): jpi, type=chain', function (t) {

  const tokenRoot = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain'
    }
  });
  const tokenChildA = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: tokenRoot
    }
  });
  const tokenChildB = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: tokenChildA
    }
  });
  const tokenParentWithoutJpi = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true
  });
  const tokenChildC = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: tokenParentWithoutJpi
    }
  });

  const dtokenRoot = ramses.decode(tokenRoot);
  const dtokenChildA = ramses.decode(tokenChildA);
  const dtokenChildB = ramses.decode(tokenChildB);
  const dtokenParentWithoutJpi = ramses.decode(tokenParentWithoutJpi);
  const dtokenChildC = ramses.decode(tokenChildC);

  t.ok((dtokenRoot.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((dtokenChildA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((dtokenChildB.payload.jpi.length == 2), 'length of jpi array of childB ticket should be 2');
  t.ok((dtokenChildC.payload.jpi.length == 1), 'length of jpi array of childC ticket should be 1');

  t.ok((dtokenChildA.payload.jpi[0] === dtokenRoot.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((dtokenChildB.payload.jpi[0] === dtokenRoot.payload.jti && dtokenChildB.payload.jpi[1] === dtokenChildA.payload.jti), 'uuids of jpi of childB shoud be uuid of root ticket and childA ticket');
  t.ok((dtokenChildC.payload.jpi[0] === dtokenParentWithoutJpi.payload.jti), 'uuid of jpi of childC shoud be uuid of parent without jpi ticket');

  t.end();
});

test('ramses.sign(): jpi, throw errors', function (t) {
  const payload = {
    "key": "value"
  }
  const tokenWithoutJti = ramses.sign(payload, keys.rsaPrivateKey);

  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'invalid type'
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'parent',
        parent: 'invalidticket'
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'parent',
        parent: tokenWithoutJti
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'root',
        parent: tokenWithoutJti
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'chain',
        parent: tokenWithoutJti
      }
    });
  });

  t.end();
});

test('ramses.sign(): encrypt', function (t) {
  const payload = {
    "key": "value"
  }
  const token = ramses.sign(payload, keys.rsaPrivateKey, options = {
    encrypt: [{
      aud: ['Audience'],
      alg: 'RSA',
      key: keys.rsaPublicKey,
      content: 'correct message'
    }]
  });

  const dtoken = ramses.decode(token, options = {
    decrypt: {
      aud: 'Audience',
      key: keys.rsaPrivateKey
    }
  });

  t.ok(dtoken.payload.epd[0].dct === 'correct message', 'dct should exist in epd');
  t.end();
});

test('ramses.sign(): encrypt', function (t) {
  const payload = {
    "key": "value"
  }

  const tokenWrong = ramses.sign(payload, keys.rsaPrivateKey, options = {
    encrypt: [{
      aud: ['Audience'],
      alg: 'wrongAlgorithm',
      key: keys.rsaPublicKey,
      content: 'correct message'
    }]
  });

  const dtokenWrong = ramses.decode(tokenWrong, options = {
    decrypt: {
      aud: 'Audience',
      key: keys.rsaPrivateKey
    }
  });

  t.ok(!dtokenWrong.payload.epd, 'no epd should exist');
  t.end();
});
