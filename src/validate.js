const decode = require('./decode');
const verify = require('./verify');

function validate(token, key, options = {}) {
  if (options.alg) {
    if (!verify(token, key, options = {
        alg: options.alg
      })) {
      return false;
    }
  } else {
    if (!verify(token, key)) {
      return false;
    }
  }

  dtoken = decode(token);
  if (dtoken.payload.exp && dtoken.payload.exp < Math.floor(new Date().getTime() / 1000)) {
    return false;
  }
  if (options.aud && (!dtoken.payload.aud || dtoken.payload.aud.indexOf(options.aud) == -1)) {
    return false;
  }
  if (options.azp && (!dtoken.payload.azp || dtoken.payload.azp.indexOf(options.azp) == -1)) {
    return false;
  }
  return true;
}

module.exports = validate;
