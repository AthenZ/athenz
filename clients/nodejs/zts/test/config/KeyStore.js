'use strict';

var fs = require('fs');

class KeyStore {
    static getPublicKey(domain, service, keyId) {
        if (!domain || !service || !keyId) {
            return null;
        }
        return fs.readFileSync(__dirname + '/../resources/public_k0.pem');
    }
}

module.exports = KeyStore;
