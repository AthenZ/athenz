'use strict';

var fs = require('fs');

class KeyStore {
  static getPublicKey(domain, service, keyId) {
    if (!domain || !service || !keyId) {
      return null;
    }
    return fs.readFileSync('keys/' + domain.toString().toLowerCase() + '.' + service.toString().toLowerCase() + '.v' + keyId + '.*');
  }
}

module.exports = KeyStore;
