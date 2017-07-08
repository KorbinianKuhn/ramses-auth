const jwa = require('jwa');
const decode = require('./decode');
const error = require('./error');

function verify(ticket, key, options = {}) {
  if (!options.alg) {
    var algorithm = decode(ticket).header.alg;
  } else {
    var algorithm = options.alg;
  }

  const content = ticket.split('.', 2).join('.');
  const signature = ticket.split('.')[2];

  const algo = jwa(algorithm);
  return algo.verify(content, signature, key);
}

module.exports = verify;
