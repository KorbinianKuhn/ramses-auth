const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys')

const ALGORITHMS = ramses.ALGORITHMS;


test('ramses.sign()', function (t) {
  const payload = {
    "key": "value"
  }
  const ticket = ramses.sign(payload, keys.rsaPrivateKey);

  t.ok(ramses.decode(ticket), 'correct key should decode');
  t.ok(ramses.verify(ticket, keys.rsaPublicKey), 'correct key should verify');
  t.end();
});

ALGORITHMS.forEach(function (alg) {
  test('ramses.sign(): algorithm ' + alg, function (t) {
    const payload = {
      "key": "value"
    }
    const ticket = ramses.sign(payload, keys.rsaPrivateKey, options = {
      alg: alg
    });

    t.ok(ramses.verify(ticket, keys.rsaPublicKey, algorithm = alg)), 'should verify';
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
  const ticket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true
  });

  const decodedTicket = ramses.decode(ticket);
  t.ok(('jti' in decodedTicket.payload), 'jti should exist in payload');

  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  t.ok(decodedTicket.payload.jti.match(uuidPattern), 'jti should match uuid pattern');

  t.end();
});

test('ramses.sign(): exp', function (t) {
  const payload = {
    "key": "value"
  }
  const ticket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    exp: true
  });

  const decodedTicket = ramses.decode(ticket);

  t.ok(('exp' in decodedTicket.payload), 'exp should exist in payload');

  t.end();
});

test('ramses.sign(): jpi', function (t) {
  const payload = {
    "key": "value"
  }
  const rootTicket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {}
  });
  const childTicketA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      parent: rootTicket
    }
  });
  const childTicketB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      parent: childTicketA
    }
  });

  const decodedRootTicket = ramses.decode(rootTicket);
  const decodedChildTicketA = ramses.decode(childTicketA);
  const decodedChildTicketB = ramses.decode(childTicketB);

  t.ok((decodedRootTicket.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((decodedChildTicketA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((decodedChildTicketB.payload.jpi.length == 2), 'length of jpi array of childB ticket should be 2');

  t.ok((decodedChildTicketA.payload.jpi[0] === decodedRootTicket.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((decodedChildTicketB.payload.jpi[0] === decodedRootTicket.payload.jti && decodedChildTicketB.payload.jpi[1] === decodedChildTicketA.payload.jti), 'uuids of jpi of childB shoud be uuid of root ticket and childA ticket');

  t.end();
});

test('ramses.sign(): jpi, type=root', function (t) {
  const payload = {
    "key": "value"
  }
  const rootTicket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root'
    }
  });
  const childTicketA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root',
      parent: rootTicket
    }
  });
  const childTicketB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'root',
      parent: childTicketA
    }
  });

  const decodedRootTicket = ramses.decode(rootTicket);
  const decodedChildTicketA = ramses.decode(childTicketA);
  const decodedChildTicketB = ramses.decode(childTicketB);

  t.ok((decodedRootTicket.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((decodedChildTicketA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((decodedChildTicketB.payload.jpi.length == 1), 'length of jpi array of childB ticket should be 1');

  t.ok((decodedChildTicketA.payload.jpi[0] === decodedRootTicket.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((decodedChildTicketB.payload.jpi[0] === decodedRootTicket.payload.jti), 'uuid of jpi of childB shoud be uuid of root ticket');

  t.end();
});

test('ramses.sign(): jpi, type=parent', function (t) {
  const payload = {
    "key": "value"
  }
  const rootTicket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent'
    }
  });
  const childTicketA = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent',
      parent: rootTicket
    }
  });
  const childTicketB = ramses.sign(payload, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'parent',
      parent: childTicketA
    }
  });

  const decodedRootTicket = ramses.decode(rootTicket);
  const decodedChildTicketA = ramses.decode(childTicketA);
  const decodedChildTicketB = ramses.decode(childTicketB);

  t.ok((decodedRootTicket.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((decodedChildTicketA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((decodedChildTicketB.payload.jpi.length == 1), 'length of jpi array of childB ticket should be 1');

  t.ok((decodedChildTicketA.payload.jpi[0] === decodedRootTicket.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((decodedChildTicketB.payload.jpi[0] === decodedChildTicketA.payload.jti), 'uuid of jpi of childB shoud be uuid of childA ticket');

  t.end();
});

test('ramses.sign(): jpi, type=chain', function (t) {

  const rootTicket = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain'
    }
  });
  const childTicketA = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: rootTicket
    }
  });
  const childTicketB = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: childTicketA
    }
  });
  const parentWithoutJpi = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true
  });
  const childTicketC = ramses.sign({
    "key": "value"
  }, keys.rsaPrivateKey, options = {
    jti: true,
    jpi: {
      type: 'chain',
      parent: parentWithoutJpi
    }
  });

  const decodedRootTicket = ramses.decode(rootTicket);
  const decodedChildTicketA = ramses.decode(childTicketA);
  const decodedChildTicketB = ramses.decode(childTicketB);
  const decodedParentWithoutJpi = ramses.decode(parentWithoutJpi);
  const decodedChildTicketC = ramses.decode(childTicketC);

  t.ok((decodedRootTicket.payload.jpi.length == 0), 'length of jpi array of root ticket should be empty');
  t.ok((decodedChildTicketA.payload.jpi.length == 1), 'length of jpi array of childA ticket should be 1');
  t.ok((decodedChildTicketB.payload.jpi.length == 2), 'length of jpi array of childB ticket should be 2');
  t.ok((decodedChildTicketC.payload.jpi.length == 1), 'length of jpi array of childC ticket should be 1');

  t.ok((decodedChildTicketA.payload.jpi[0] === decodedRootTicket.payload.jti), 'uuid of jpi of childA shoud be uuid of root ticket');
  t.ok((decodedChildTicketB.payload.jpi[0] === decodedRootTicket.payload.jti && decodedChildTicketB.payload.jpi[1] === decodedChildTicketA.payload.jti), 'uuids of jpi of childB shoud be uuid of root ticket and childA ticket');
  t.ok((decodedChildTicketC.payload.jpi[0] === decodedParentWithoutJpi.payload.jti), 'uuid of jpi of childC shoud be uuid of parent without jpi ticket');

  t.end();
});

test('ramses.sign(): jpi, throw errors', function (t) {
  const payload = {
    "key": "value"
  }
  const ticketWithoutJti = ramses.sign(payload, keys.rsaPrivateKey);

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
        parent: ticketWithoutJti
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'root',
        parent: ticketWithoutJti
      }
    });
  });
  t.throws(function () {
    ramses.sign(payload, keys.rsaPrivateKey, options = {
      jpi: {
        type: 'chain',
        parent: ticketWithoutJti
      }
    });
  });

  t.end();
});

test('ramses.sign(): encrypt', function (t) {
  const payload = {
    "key": "value"
  }
  const ticket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    encrypt: [{
      aud: ['Audience'],
      alg: 'RSA',
      key: keys.rsaPublicKey,
      content: 'correct message'
    }]
  });

  const decodedTicket = ramses.decode(ticket, options = {
    decrypt: {
      aud: 'Audience',
      key: keys.rsaPrivateKey
    }
  });

  t.ok(decodedTicket.payload.epd[0].dct === 'correct message', 'dct should exist in epd');
  t.end();
});

test('ramses.sign(): encrypt', function (t) {
  const payload = {
    "key": "value"
  }

  const wrongEncodedTicket = ramses.sign(payload, keys.rsaPrivateKey, options = {
    encrypt: [{
      aud: ['Audience'],
      alg: 'wrongAlgorithm',
      key: keys.rsaPublicKey,
      content: 'correct message'
    }]
  });

  const wrongDecodedTicket = ramses.decode(wrongEncodedTicket, options = {
    decrypt: {
      aud: 'Audience',
      key: keys.rsaPrivateKey
    }
  });

  t.ok(!wrongDecodedTicket.payload.epd, 'no epd should exist');
  t.end();
});
