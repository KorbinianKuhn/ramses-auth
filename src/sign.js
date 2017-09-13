const jws = require('jws');
const uuidv4 = require('uuid/v4');
const decode = require('./decode');
const RSA = require('node-rsa');
const ramses = require('..');
const UnauthorizedError = require('./errors/UnauthorizedError');

function sign(payload, key, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else {
    options = options || {};
  }

  function failure(err) {
    if (callback) {
      return callback(err);
    }
    throw err;
  }

  if (!key) {
    return failure(new UnauthorizedError('missing_key', {
      message: 'Missing parameter key'
    }));
  }

  let header = {
    alg: 'RS256',
    typ: 'JWT'
  }

  if (options.alg) {
    if (ramses.ALGORITHMS.indexOf(options.alg) == -1) {
      return failure(new UnauthorizedError('invalid_algorithm', {
        message: 'Invalid value for parameter alg'
      }));
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
    let jpiType = 'root';
    if (options.jpi.type) {
      if (['parent', 'root', 'chain'].indexOf(options.jpi.type) == -1) {
        return failure(new UnauthorizedError('invalid_jpi_type', {
          message: 'Invalid value for parameter type in options.jpi'
        }));
      }
      jpiType = options.jpi.type;
    }

    if (options.jpi.parent) {
      const parentTicket = decode(options.jpi.parent);

      if (parentTicket === null) {
        return failure(new UnauthorizedError('invalid_parent_ticket', {
          message: 'Error decoding parent ticket'
        }));
      }
      if (jpiType === 'parent') {
        if (!parentTicket.payload.jti) {
          return failure(new UnauthorizedError('missing_parent_jti', {
            message: 'Missing parameter jti in parent ticket'
          }));
        } else {
          payload.jpi = [parentTicket.payload.jti];
        }
      } else if (jpiType === 'root') {
        if (parentTicket.payload.jpi && parentTicket.payload.jpi.length > 0) {
          payload.jpi = [parentTicket.payload.jpi[0]];
        } else if (parentTicket.payload.jti) {
          payload.jpi = [parentTicket.payload.jti];
        } else {
          return failure(new UnauthorizedError('missing_parent_jti_or_jpi', {
            message: 'Missing parameter jti or jpi in parent ticket'
          }));
        }
      } else {
        if (!parentTicket.payload.jti) {
          return failure(new UnauthorizedError('missing_parent_jti', {
            message: 'Missing parameter jti in parent ticket'
          }));
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

  if (options.encrypt && options.encrypt.length > 0) {
    payload.epd = [];
    for (let i = 0; i < options.encrypt.length; i++) {
      let data = options.encrypt[i];

      if (!data.content) {
        return failure(new UnauthorizedError('missing_encrypt_content', {
          message: 'Missing parameter content in encryption options'
        }));
      }

      if (!data.alg) {
        data.alg = 'RSA';
      }

      if (ramses.ENCRYPTION_ALGORITHMS.indexOf(data.alg) === -1) {
        return failure(new UnauthorizedError('invalid_encrypt_algorithm', {
          message: 'Invalid value for parameter alg in encryption options'
        }));
      }

      if (!data.aud) {
        return failure(new UnauthorizedError('missing_encrypt_audience', {
          message: 'Missing parameter aud in encryption options'
        }));
      }

      if (!data.key) {
        return failure(new UnauthorizedError('missing_encrypt_key', {
          message: 'Missing parameter key in encryption options'
        }));
      }

      let message;
      try {
        message = new RSA(data.key).encrypt(data.content, 'base64');
      } catch (err) {
        return failure(new UnauthorizedError('encryption_error', {
          message: err.message
        }));
      }

      payload.epd.push({
        aud: data.aud,
        alg: data.alg,
        ect: message
      })

    }
  }

  var token = jws.sign({
    header: header,
    payload: payload,
    secret: key
  });

  if (callback) {
    callback(null, token);
  } else {
    return token;
  }
}

module.exports = sign;
