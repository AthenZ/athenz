'use strict';

var crypto = require('crypto');
var ybase64 = require('./YBase64');

var SALT_LENGTH = 8;
var SALT_CHARS = '0123456789abcdef';

class Crypto {
  static hmac(message, sharedSecret) {
    try {
      var hmac = crypto.createHmac('sha256', sharedSecret);
      hmac.update(message);
      return ybase64.ybase64Encode(hmac.digest());
    } catch (e) {
      throw new Error('Crypto:hmac:' + e.message);
    }
  }

  static sign(message, key, digestAlgorithm) {
    try {
      var sign = crypto.createSign(digestAlgorithm);
      sign.update(message);
      return ybase64.ybase64Encode(sign.sign(key));
    } catch (e) {
      throw new Error('Crypto:sign:' + e.message);
    }
  }

  static verify(message, key, signature, digestAlgorithm) {
    try {
      var sig = ybase64.ybase64Decode(signature);
      var verify = crypto.createVerify(digestAlgorithm);
      verify.update(message);
      return verify.verify(key, sig);
    } catch (e) {
      throw new Error('Crypto:verify:' + e.message);
    }
  }

  static randomSalt() {
    var c, i, salt = '';
    for (c = 0; c < SALT_LENGTH; c++) {
      i = Math.floor(Math.random() * SALT_CHARS.length);
      salt += SALT_CHARS.charAt(i);
    }
    return salt;
  }
}

module.exports = Crypto;
