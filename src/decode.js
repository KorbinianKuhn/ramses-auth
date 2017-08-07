const jws = require('jws');
const error = require('./error');
const RSA = require('node-rsa');
const ramses = require('..');

function decode(signature, options = {}) {
  let dtoken = jws.decode(signature);
  if (options.decrypt && dtoken.payload.epd) {
    if (!options.decrypt.aud) {
      throw error('Missing parameter aud in options.decrypt', 'MISSING PARAMETER');
    }
    if (!options.decrypt.key) {
      throw error('Missing parameter key in options.decrypt', 'MISSING PARAMETER');
    }

    dtoken.payload.dct = [];
    for (let i = 0; i < dtoken.payload.epd.length; i++) {
      let epd = dtoken.payload.epd[i];
      if (epd.aud && epd.alg && ramses.ENCRYPTION_ALGORITHMS.indexOf(epd.alg) != -1 && epd.ect && epd.aud.indexOf(options.decrypt.aud) != -1) {
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
