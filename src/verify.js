const jwa = require('jwa');
const decode = require('./decode');
const RamsesError = require('./errors/RamsesError');
const ALGORITHMS = require('./algorithms');

function verify(token, key, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else {
    options = options || {};
  }

  if (callback) {
    done = callback;
  } else {
    done = function (err, data) {
      if (err) throw err;
      return data;
    };
  }

  const dtoken = decode(token);
  if (dtoken === null) {
    return done(new RamsesError('decoding_error', {
      message: 'Error decoding token'
    }));
  }

  const content = token.split('.', 2).join('.');
  const signature = token.split('.')[2];

  var valid;

  try {
    const algo = jwa(dtoken.header.alg);
    valid = algo.verify(content, signature, key);
  } catch (err) {
    return done(new RamsesError('invalid_key', {
      message: err.message
    }));
  }

  if (!valid) {
    return done(new RamsesError('invalid_token', {
      message: 'Token is invalid'
    }));
  }

  if (dtoken.payload.exp && dtoken.payload.exp < Math.floor(new Date().getTime() / 1000)) {
    return done(new RamsesError('expired_token', {
      message: 'Token has expired'
    }));
  }
  if (options.aud && (!dtoken.payload.aud || dtoken.payload.aud.indexOf(options.aud) == -1)) {
    return done(new RamsesError('wrong_audience', {
      message: 'Wrong audience'
    }));
  }
  if (options.azp && (!dtoken.payload.azp || dtoken.payload.azp.indexOf(options.azp) == -1)) {
    return done(new RamsesError('wrong_authorized_party', {
      message: 'Wrong authorized party'
    }));
  }

  if (options.isValidCallback) {
    options.isValidCallback(dtoken, function (err, dtoken) {
      return done(err, dtoken);
    });
  } else {
    return done(null, dtoken);
  }
}

module.exports = verify;
