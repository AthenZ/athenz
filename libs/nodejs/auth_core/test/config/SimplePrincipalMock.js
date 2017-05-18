'use strict';

class SimplePrincipalMock {
  constructor (domain){
    this._domain = domain;
  }

  setDomain(domain) {
    this._domain = domain;
  }

  getDomain(domain) {
    return this._domain;
  }
}

module.exports = SimplePrincipalMock;
