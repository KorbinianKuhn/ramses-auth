function RamsesError(code, error) {
  this.name = "RamsesError";
  this.message = error.message;
  Error.call(this, error.message);
  Error.captureStackTrace(this, this.constructor);
  this.code = code;
  this.status = 401;
  this.inner = error;
}

RamsesError.prototype = Object.create(Error.prototype);
RamsesError.prototype.constructor = RamsesError;

module.exports = RamsesError;
