'use strict';

class PrincipalAuthorityMock {
  static getPublicKey(domain, service, keyId) {
    if (!domain || !service || !keyId) {
      return null;
    }

    return domain + '.' + service + '.' + keyId;
  }
}

module.exports = PrincipalAuthorityMock;
