const jws = require('jws');
const error = require('./error');
const RSA = require('node-rsa');
const ramses = require('..');

function decode(signature, options = {}) {
  let ticket = jws.decode(signature);
  if (options.decrypt && ticket.payload.epd) {
    if (!options.decrypt.aud) {
      throw error('Missing parameter aud in options.decrypt', 'MISSING PARAMETER');
    }
    if (!options.decrypt.key) {
      throw error('Missing parameter key in options.decrypt', 'MISSING PARAMETER');
    }

    ticket.payload.dct = [];
    for (let i = 0; i < ticket.payload.epd.length; i++) {
      let epd = ticket.payload.epd[i];
      if (epd.aud && epd.alg && ramses.ENCRYPTION_ALGORITHMS.indexOf(epd.alg) != -1 && epd.ect && epd.aud.indexOf(options.decrypt.aud) != -1) {
        try {
          ticket.payload.epd[i].dct = new RSA(options.decrypt.key).decrypt(epd.ect, 'utf8');
        } catch (err) {
          //do nothing if decryption failed
        }
      }
    }
  }
  return ticket;
}

module.exports = decode;
