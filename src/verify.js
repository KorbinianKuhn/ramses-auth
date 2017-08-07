const jwa = require('jwa');
const decode = require('./decode');
const error = require('./error');

function verify(token, key, options = {}) {
  if (!options.alg) {
    const dtoken = decode(token);
    if (dtoken === null) {
      return false;
    }
    var algorithm = dtoken.header.alg;
  } else {
    var algorithm = options.alg;
  }

  const content = token.split('.', 2).join('.');
  const signature = token.split('.')[2];

  const algo = jwa(algorithm);
  return algo.verify(content, signature, key);
}

module.exports = verify;
