'use strict';

class Validate {
  static principalName(name) {
    var reg = new RegExp('((([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*):)?(([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*)');
    return this._checkReg(reg, name);
  }

  static domainName(name) {
    var reg = new RegExp('([a-zA-Z_][a-zA-Z0-9_-]*\\.)*[a-zA-Z_][a-zA-Z0-9_-]*');
    return this._checkReg(reg, name);
  }

  static _checkReg(reg, name) {
    var result = reg.exec(name);
    return (result && result[0] === name) ? true : false;
  }
}

module.exports = Validate;
