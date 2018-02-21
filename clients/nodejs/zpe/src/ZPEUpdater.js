'use strict';

const fs = require('fs');
const winston = require('winston');

let config = require('../config/config')();
const Crypto = require('@athenz/auth-core').Crypto;
const ZPEMatch = require('./ZPEMatch');

let _roleCache = require('memory-cache');
let _policyCache = require('memory-cache');
let _zpeClt;

class ZPEUpdater {
  static setConfig(c) {
    config = Object.assign({}, config, c.zpeClient);
  }

  static setZPEClient(zpeClt) {
    _zpeClt = zpeClt;
  }

  static getRoleTokenCacheMap() {
    return _roleCache;
  }

  static getWildcardAllowAssertions(domain) {
    let roleMap = this._lookupPolicyInCache(domain);
    return roleMap.wildcardRoleAllowMap;
  }

  static getRoleAllowAssertions(domain) {
    let roleMap = this._lookupPolicyInCache(domain);
    return roleMap.standardRoleAllowMap;
  }

  static getWildcardDenyAssertions(domain) {
    let roleMap = this._lookupPolicyInCache(domain);
    return roleMap.wildcardRoleDenyMap;
  }

  static getRoleDenyAssertions(domain) {
    let roleMap = this._lookupPolicyInCache(domain);
    return roleMap.standardRoleDenyMap;
  }

  static loadFiles(polDir) {
    winston.debug("loadFiles: load start directory=" + polDir);
    let files = fs.readdirSync(polDir)
                  .filter((fileName) => fileName.endsWith(".pol"));

    for (let fileName of files) {
      winston.debug("loadFiles: load start file name=" + fileName);
      let path = polDir + '/' + fileName;

      let spols = JSON.parse(fs.readFileSync(path, 'utf8'));

      if (!spols) {
        winston.error("loadFile: unable to decode domain file=" + fileName);
        return;
      }

      let signedPolicyData = spols.signedPolicyData;
      let signature = spols.signature;
      let keyId = spols.keyId;

      // first let's verify the ZTS signature for our policy file
      let verified = false;

      if (signedPolicyData) {
        let pubKey = _zpeClt.getZtsPublicKey(keyId);
        verified = Crypto.verify(this._asCanonicalString(signedPolicyData), pubKey, signature, 'SHA256');
      }

      let policyData = null;
      if (verified) {
        // now let's verify that the ZMS signature for our policy file
        policyData = signedPolicyData.policyData;
        signature = signedPolicyData.zmsSignature;
        keyId = signedPolicyData.zmsKeyId;

        if (policyData) {
          let pubKey = _zpeClt.getZmsPublicKey(keyId);
          verified = Crypto.verify(this._asCanonicalString(policyData), pubKey, signature, 'SHA256');
        }
      }

      if (!verified) {
        winston.error("loadFile: policy file=" + fileName + " is invalid");
        return;
      }

      this._loadPolicies(policyData, fileName);
    }
  }

  static _loadPolicies(policyData, fileName) {
    // HAVE: valid policy file
    let domainName = policyData.domain;

    winston.debug("loadFile: policy file(" + fileName + ") for domain(" + domainName + ") is valid");

    // Process the policies into assertions, process the assertions: action, resource, role
    // If there is a wildcard in the action or resource, compile the
    // regexpr and place it into the assertion Struct.
    // This is a performance enhancement for AuthZpeClient when it
    // performs the authorization checks.

    let roleStandardAllowMap = {};
    let roleWildcardAllowMap = {};
    let roleStandardDenyMap = {};
    let roleWildcardDenyMap = {};

    let policies = policyData.policies;

    for (let policy of policies) {
      let assertions = policy.assertions;
      let pname = policy.name;

      winston.debug("loadFile: domain(" + domainName + ") policy(" + pname + ")");

      if (!assertions) {
        continue;
      }

      for (let assertion of assertions) {
        let assert = {};
        assert.polname = pname;

        assert.action = assertion.action;
        assert.actionMatchStruct = this._getMatchObject(assert.action);

        assert.resource = _zpeClt.stripDomainPrefix(assertion.resource, domainName, assertion.resource);
        assert.resourceMatchStruct = this._getMatchObject(assert.resource);

        assert.role = _zpeClt.stripDomainPrefix(assertion.role, domainName, assertion.role);
        // strip the prefix "role." too
        assert.role = assert.role.replace(/^role./, '');
        assert.roleMatchStruct = this._getMatchObject(assert.role);

        let matchStruct = assert.roleMatchStruct;
        let roleMap = null;

        if (assertion.effect === 'DENY') {
          if (matchStruct.name === 'equal') {
            roleMap = roleStandardDenyMap;
          } else {
            roleMap = roleWildcardDenyMap;
          }
        } else {
          if (matchStruct.name === 'equal') {
            roleMap = roleStandardAllowMap;
          } else {
            roleMap = roleWildcardAllowMap;
          }
        }

        let assertList = roleMap[assert.role];
        if (!assertList) {
          roleMap[assert.role] = [];
        }
        roleMap[assert.role].push(assert);
      }
    }

    _policyCache.put(
      domainName,
      {
        standardRoleAllowMap: roleStandardAllowMap,
        wildcardRoleAllowMap: roleWildcardAllowMap,
        standardRoleDenyMap: roleStandardDenyMap,
        wildcardRoleDenyMap: roleWildcardDenyMap
      },
      config.policyRefresh * 1000
    );
  }

  static _lookupPolicyInCache(domain) {
    let roleMap = _policyCache.get(domain);

    if (!roleMap) {
      winston.debug("_lookupPolicyInCache: Policy Cache Miss");
      this.loadFiles(config.policyDir);
    } else {
      winston.debug("_lookupPolicyInCache: Policy Cache Hit");
    }

    return _policyCache.get(domain) || {};
  }

  static _asCanonicalString(obj) {
    let str = '';
    if (typeof(obj) === 'object' && !Array.isArray(obj)) {
      str += '{';
      for (let key of Object.keys(obj).sort()) {
        str += '"' + key + '":' + this._asCanonicalString(obj[key]);
        str += ",";
      }
      str = this._deleteEndSeparator(str);
      str += '}';
    } else if (typeof(obj) === 'object') {
      str += '[';
      for(let item of obj) {
        str += this._asCanonicalString(item);
        str += ',';
      }
      str = this._deleteEndSeparator(str);
      str += ']';
    } else if (typeof(obj) === 'string') {
      str += '"' + obj + '"';
    } else if (typeof(obj) === 'number') {
      str += String(obj);
    }

    return str;
  }

  static _deleteEndSeparator(str) {
    if (str[str.length - 1] === ',') {
      str = str.substring(0, str.length - 1);
    }

    return str;
  }

  static _getMatchObject(value) {
    let res = {};
    let matches = null;
    const matchGen = ZPEMatch(value);

    if (value === '*') {
      res = matchGen.all;
    } else {
      let anyCharMatch = value.indexOf('*');
      let singleCharMatch = value.indexOf('?');

      if (anyCharMatch === -1 && singleCharMatch === -1) {
        res = matchGen.equal;
      } else if (anyCharMatch === value.length - 1 && singleCharMatch === -1) {
        res = matchGen.startswith;
      } else if (anyCharMatch === 0 && singleCharMatch === -1) {
        res = matchGen.endswith;
      } else {
        res = matchGen.regex;
      }
    }

    return res;
  }
}

module.exports = ZPEUpdater;
