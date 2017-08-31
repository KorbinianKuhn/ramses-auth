const jws = require('jws');
const uuidv4 = require('uuid/v4');
const error = require('./error');
const decode = require('./decode');
const RSA = require('node-rsa');
const ramses = require('..');

function sign(payload, key, options = {}) {
  let header = {
    alg: 'RS256',
    typ: 'JWT'
  }

  if (options.alg) {
    if (ramses.ALGORITHMS.indexOf(options.alg) == -1) {
      throw error("Invalid value for parameter alg", "INVALID_PARAMETER");
    }
    header.alg = options.alg;
  }

  if (options.jti) {
    payload.jti = uuidv4();
  }

  if (options.ttl) {
    payload.exp = Math.floor(new Date().getTime() / 1000) + options.ttl;
  }

  if (options.jpi) {
    let jpiType = 'chain';
    if (options.jpi.type) {
      if (['parent', 'root', 'chain'].indexOf(options.jpi.type) == -1) {
        throw error("Invalid value for parameter type in options.jpi", "INVALID_VALUE");
      }
      jpiType = options.jpi.type;
    }

    if (options.jpi.parent) {
      const parentTicket = decode(options.jpi.parent);

      if (parentTicket === null) {
        throw error("Decoding error for value of options.jpi.parent", "DECODING_ERROR");
      }
      if (jpiType === 'parent') {
        if (!parentTicket.payload.jti) {
          throw error("Missing parameter jti in parent ticket", "MISSING_PARAMETER");
        } else {
          payload.jpi = [parentTicket.payload.jti];
        }
      } else if (jpiType === 'root') {
        if (parentTicket.payload.jpi && parentTicket.payload.jpi.length > 0) {
          payload.jpi = [parentTicket.payload.jpi[0]];
        } else if (parentTicket.payload.jti) {
          payload.jpi = [parentTicket.payload.jti];
        } else {
          throw error("Missing parameter jti or jpi in parent ticket", "MISSING_PARAMETER");
        }
      } else {
        if (!parentTicket.payload.jti) {
          throw error("Missing parameter jti in parent ticket", "MISSING_PARAMETER");
        } else {
          if (parentTicket.payload.jpi) {
            payload.jpi = parentTicket.payload.jpi;
          } else {
            payload.jpi = [];
          }
          payload.jpi.push(parentTicket.payload.jti);
        }
      }
    } else {
      payload.jpi = [];
    }
  }

  if (options.encrypt) {
    let epd = [];
    for (let i = 0; i < options.encrypt.length; i++) {
      let data = options.encrypt[i];
      if (data.content && data.alg && ramses.ENCRYPTION_ALGORITHMS.indexOf(data.alg) != -1 && data.aud && data.key) {
        try {
          epd.push({
            aud: data.aud,
            alg: data.alg,
            ect: new RSA(data.key).encrypt(data.content, 'base64')
          })
        } catch (err) {
          //Do nothing if encryption failed
        }

      }
    }
    if (epd.length > 0) {
      payload.epd = epd;
    }
  }

  return jws.sign({
    header: header,
    payload: payload,
    secret: key
  })
}

module.exports = sign;
