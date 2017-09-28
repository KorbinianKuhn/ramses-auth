const jws = require('jws');
const RSA = require('node-rsa');
const ramses = require('..');

function decode(signature, options) {
  var dtoken = jws.decode(signature);
  if (dtoken === null) {
    return null;
  }

  options = options || {};

  if (options.decrypt && dtoken.payload.epd && options.decrypt.aud && options.decrypt.key) {
    dtoken.payload.dct = [];
    for (let i = 0; i < dtoken.payload.epd.length; i++) {
      let epd = dtoken.payload.epd[i];
      if (epd.aud && epd.alg && ramses.ENCRYPTION_ALGORITHMS.indexOf(epd.alg) != -1 && epd.ect && epd.aud.indexOf(
          options.decrypt.aud) != -1) {
        try {
          dtoken.payload.epd[i].dct = new RSA(options.decrypt.key).decrypt(epd.ect, 'utf8');
        } catch (err) {
          //do nothing if decryption failed
        }
      }
    }
  }

  return dtoken;
}

module.exports = decode;
