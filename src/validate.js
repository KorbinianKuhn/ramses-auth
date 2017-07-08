const decode = require('./decode');
const verify = require('./verify');

function validate(ticket, key, options = {}) {
  if (options.alg) {
    if (!verify(ticket, key, options = {
        alg: options.alg
      })) {
      return false;
    }
  } else {
    if (!verify(ticket, key)) {
      return false;
    }
  }

  ticket = decode(ticket);
  if (ticket.payload.exp && ticket.payload.exp < Math.floor(new Date().getTime() / 1000)) {
    return false;
  }
  if (options.aud && (!ticket.payload.aud || ticket.payload.aud.indexOf(options.aud) == -1)) {
    return false;
  }
  if (options.azp && (!ticket.payload.azp || ticket.payload.azp.indexOf(options.azp) == -1)) {
    return false;
  }
  return true;
}

module.exports = validate;
