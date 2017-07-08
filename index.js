const sign = require('./src/sign');
const decode = require('./src/decode');
const verify = require('./src/verify');
const validate = require('./src/validate');

const ALGORITHMS = [
  'RS256', 'RS384', 'RS512'
];

const ENCRYPTION_ALGORITHMS = [
  'RSA'
];

exports.ALGORITHMS = ALGORITHMS;
exports.ENCRYPTION_ALGORITHMS = ENCRYPTION_ALGORITHMS;
exports.sign = sign;
exports.decode = decode;
exports.verify = verify;
exports.validate = validate;
