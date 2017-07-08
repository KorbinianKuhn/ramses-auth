function error(errorMessage, errorCode) {
  const err = new Error(errorMessage);
  err.code = errorCode;
  return err;
}

module.exports = error;
