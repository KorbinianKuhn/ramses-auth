const assert = require('assert');
const ramses = require('..');
const keys = require('./keys')
const ALGORITHMS = ramses.ALGORITHMS;

describe('verify', function () {
  var token = ramses.sign({
    param: 'value'
  }, keys.rsaPrivateKey)

  it('no options should verify', function () {
    ramses.verify(token, keys.rsaPublicKey, function (err, dtoken) {
      assert.equal(err, null);
      assert.equal(dtoken.payload.param, 'value');
    })
  });

  it('invalid token should throw', function () {
    ramses.verify('wrong', keys.rsaPublicKey, function (err, dtoken) {
      assert.equal(err.code, 'decoding_error');
    })
  });

  it('wrong key should throw', function () {
    ramses.verify(token, keys.rsaWrongPublicKey, function (err, dtoken) {
      assert.equal(err.code, 'invalid_token');
    })
  });

  it('invalid key should throw', function () {
    ramses.verify(token, 'wrong', function (err, dtoken) {
      assert.equal(err.code, 'invalid_key');
    })
  });

  it('expired token should throw', function () {
    var token = ramses.sign({
      param: 'value'
    }, keys.rsaPrivateKey, {
      ttl: -300
    })

    ramses.verify(token, keys.rsaPublicKey, function (err, dtoken) {
      assert.equal(err.code, 'expired_token');
    })
  });

  it('wrong audience should throw', function () {
    var token = ramses.sign({
      param: 'value',
      aud: ['Audience']
    }, keys.rsaPrivateKey)

    ramses.verify(token, keys.rsaPublicKey, {
      aud: 'WrongAudience'
    }, function (err, dtoken) {
      assert.equal(err.code, 'wrong_audience');
    })
  });

  it('wrong authorized party should throw', function () {
    var token = ramses.sign({
      param: 'value',
      azp: ['AuthorizedParty']
    }, keys.rsaPrivateKey)

    ramses.verify(token, keys.rsaPublicKey, {
      azp: 'WrongAuthorizedParty'
    }, function (err, dtoken) {
      assert.equal(err.code, 'wrong_authorized_party');
    })
  });

  it('custom isValidCallback should throw', function () {
    ramses.verify(token, keys.rsaPublicKey, {
      isValidCallback: function (dtoken, done) {
        done(new Error('custom_error'));
      }
    }, function (err, dtoken) {
      assert.equal(err.message, 'custom_error');
    })
  });

  it('custom isValidCallback should verify', function () {
    ramses.verify(token, keys.rsaPublicKey, {
      isValidCallback: function (dtoken, done) {
        done(null, dtoken);
      }
    }, function (err, dtoken) {
      assert.equal(err, null);
      assert.equal(dtoken.payload.param, 'value');
    })
  });
});
