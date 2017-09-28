const assert = require('assert');
const ramses = require('..');
const keys = require('./keys')
const ALGORITHMS = ramses.ALGORITHMS;

describe('sign', function () {

  describe('general', function () {

    it('missing key should throw', function () {
      ramses.sign({
        param: 'value'
      }, null, function (err) {
        assert.equal(err.code, 'missing_key');
      });
    });

    it('correct params should decode', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {}, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.param, 'value');
      });
    });

  });

  describe('optional parameters', function () {

    it('correct alg should sign', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        alg: 'RS512'
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.header.alg, 'RS512');
      });
    });

    it('wrong algorithm should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        alg: 'wrong'
      }, function (err) {
        assert.equal(err.code, 'invalid_algorithm');
      });
    });

    it('jti should match uuid pattern', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {}, function (err, token) {
        dtoken = ramses.decode(token);
        const uuidPattern =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        assert.equal(err, null);
        assert.ok(dtoken.payload.jti.match(uuidPattern));
      });
    });

    it('jti should not be set', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jti: false
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jti, undefined);
      });
    })

    it('iat should be integer by default', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {}, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.ok(Number.isInteger(dtoken.payload.iat));
      });
    })

    it('iat should be integer', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        iat: true
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.ok(Number.isInteger(dtoken.payload.iat));
      });
    })

    it('iat should not be set', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        iat: false
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.iat, undefined);
      });
    })

    it('ttl should create exp in claim payload', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        ttl: 300
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.ok(dtoken.payload.exp);
      });
    });

  });

  describe('jpi options', function () {
    it('wrong jpi type should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'wrong'
        }
      }, function (err) {
        assert.equal(err.code, 'invalid_jpi_type');
      });
    });

    var parent = ramses.sign({
      param: 'value'
    }, keys.rsaPrivateKey, {
      jti: false
    });

    it('missing jti in parent ticket should throw (jpi type parent)', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'parent',
          parent: parent
        },
        jti: false
      }, function (err) {
        assert.equal(err.code, 'missing_parent_jti');
      });
    });

    it('missing jti or jpi in parent ticket should throw (jpi type root)', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'root',
          parent: parent
        }
      }, function (err) {
        assert.equal(err.code, 'missing_parent_jti_or_jpi');
      });
    });

    it('missing jti or jpi in parent ticket should throw (jpi type chain)', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'chain',
          parent: parent
        }
      }, function (err) {
        assert.equal(err.code, 'missing_parent_jti');
      });
    });

    it('invalid parent ticket should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'parent',
          parent: 'wrong'
        }
      }, function (err) {
        assert.equal(err.code, 'invalid_parent_ticket');
      });
    });

    it('ticket should contain parent jti', function () {
      var parent_token = ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 1);
        assert.equal(dtoken.payload.jpi.indexOf(parent_dtoken.payload.jti), 0);
      });
    });

    it('ticket should contain parent jti (jpi type parent)', function () {
      var parent_token = ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'parent',
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 1);
        assert.equal(dtoken.payload.jpi.indexOf(parent_dtoken.payload.jti), 0);
      });
    });

    it('ticket should contain parent jpi (jpi type root)', function () {
      var parent_token = ramses.sign({
        jpi: ['d4bec8aa-9aa8-452a-aaaf-036451d53b91']
      }, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'root',
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 1);
        assert.equal(dtoken.payload.jpi.indexOf('d4bec8aa-9aa8-452a-aaaf-036451d53b91'), 0);
      });
    });

    it('ticket should contain parent jti (jpi type root)', function () {
      var parent_token = ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'root',
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 1);
        assert.equal(dtoken.payload.jpi.indexOf(parent_dtoken.payload.jti), 0);
      });
    });

    it('ticket should contain parent jpi and jti (jpi type chain)', function () {
      var parent_token = ramses.sign({
        jpi: ['d4bec8aa-9aa8-452a-aaaf-036451d53b91']
      }, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'chain',
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 2);
      });
    });

    it('ticket should contain parent jti (jpi type chain)', function () {
      var parent_token = ramses.sign({}, keys.rsaPrivateKey, {
        jti: true
      });
      var parent_dtoken = ramses.decode(parent_token);

      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'chain',
          parent: parent_token
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 1);
      });
    });

    it('ticket should contain empty jpi chain (jpi type chain without parent)', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        jpi: {
          type: 'chain'
        }
      }, function (err, token) {
        dtoken = ramses.decode(token);
        assert.equal(err, null);
        assert.equal(dtoken.payload.jpi.length, 0);
      });
    });

  });

  describe('encryption', function () {

    it('missing parameter content should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{

        }]
      }, function (err, token) {
        assert.equal(err.code, 'missing_encrypt_content');
      });
    });

    it('invalid parameter alg should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{
          content: 'test',
          alg: 'wrong'
        }]
      }, function (err, token) {
        assert.equal(err.code, 'invalid_encrypt_algorithm');
      });
    });

    it('missing parameter aud should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{
          content: 'test',
        }]
      }, function (err, token) {
        assert.equal(err.code, 'missing_encrypt_audience');
      });
    });

    it('missing parameter key should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{
          content: 'test',
          aud: ['Audience']
        }]
      }, function (err, token) {
        assert.equal(err.code, 'missing_encrypt_key');
      });
    });

    it('invalid parameter key should throw', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{
          content: 'test',
          aud: ['Audience'],
          key: 'wrong'
        }]
      }, function (err, token) {
        assert.equal(err.code, 'encryption_error');
      });
    });

    it('should contain encrypted content', function () {
      ramses.sign({
        param: 'value'
      }, keys.rsaPrivateKey, {
        encrypt: [{
          content: 'test',
          aud: ['Audience'],
          key: keys.rsaPublicKey
        }]
      }, function (err, token) {
        dtoken = ramses.decode(token, {
          decrypt: {
            aud: 'Audience',
            key: keys.rsaPrivateKey
          }
        });
        assert.equal(err, null);
        assert.equal(dtoken.payload.epd[0].dct, 'test');
      });
    });

  });

});
