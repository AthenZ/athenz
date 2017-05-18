'use strict';

class YBase64 {
  static ybase64Encode(input) {
    var buffer = (Buffer.isBuffer(input)) ? input : new Buffer(input);
    var encoded = buffer.toString('base64');
    return encoded.replace(/\+/g, '.').replace(/\//g, '_').replace(/=/g, '-');
  }

  static ybase64Decode(input) {
    if ('string' !== typeof input) {
      throw new Error(input + ' is not string');
    }
    var encoded = input.replace(/\./g, '+').replace(/_/g, '/').replace(/-/g, '=');
    return new Buffer(encoded, 'base64');
  }
}

module.exports = YBase64;
