'use strict';

const winston = require('winston');

let config = require('../config/config')();
const RoleToken = require('auth_core').RoleToken;
const AccessCheckStatus = require('./AccessCheckStatus');
const PublicKeyStore = require('./PublicKeyStore');
const ZPEUpdater = require('./ZPEUpdater');

let _publicKeyStore,
  _allowedOffset;

let initialized = false;

class AuthZPEClient {

  static init() {
    if (!initialized) {
      winston.level = config.logLevel;

      _publicKeyStore = new PublicKeyStore();
      _allowedOffset = Number(config.allowedOffset);
      if (_allowedOffset < 0) {
        _allowedOffset = 300;
      }

      ZPEUpdater.setZPEClient(AuthZPEClient);

      initialized = true;
    }
  }

  static setConfig(c) {
    config = Object.assign({}, config, c.zpeClient);
    PublicKeyStore.setConfig(c);
    ZPEUpdater.setConfig(c);
  }

  static getZtsPublicKey(keyId) {
    this.init();
    return _publicKeyStore.getZtsKey(keyId);
  }

  static getZmsPublicKey(keyId) {
    this.init();
    return _publicKeyStore.getZmsKey(keyId);
  }

  static allowAccess(params, cb) {
    this.init();
    let roleToken = params.roleToken,
        resource = params.resource,
        action = params.action;

    if (!roleToken || !resource || !action) {
      return cb('ERROR: paramater must include 3 members: roleToken, resource, action',
        AccessCheckStatus.DENY_INVALID_PARAMETERS);
    }

    winston.debug("allowAccess: action=" + action + " resource=" + resource);

    let tokenCache = ZPEUpdater.getRoleTokenCacheMap();
    let rToken = tokenCache.get(roleToken);

    if (!rToken) {
      winston.debug("allowAccess: Role Token Cache Miss");

      rToken = new RoleToken(roleToken);

      let pubKey = this.getZtsPublicKey(rToken.getKeyId());
      if (rToken.validate(pubKey, _allowedOffset, true) === false) {
        winston.error("allowAccess: Authorization denied. Authentication of token failed for token=" +
          rToken.getSignedToken());
        return cb('ERROR: Invalid Role Token', AccessCheckStatus.DENY_ROLETOKEN_INVALID);
      }

      if (tokenCache) {
        tokenCache.put(roleToken, rToken, config.tokenRefresh * 1000);
      }
    } else {
      winston.debug("allowAccess: Role Token Cache Hit");
    }

    delete params.roleToken;
    params.rToken = rToken;

    return this._allowAccessByTokenObj(params, cb);
  }

  static _allowAccessByTokenObj(params, cb) {
    let rToken = params.rToken,
        resource = params.resource,
        action = params.action;
    if (!rToken) {
      winston.error("allowAccess: Authorization denied. Token is null");
      return cb(null, AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    const now = Date.now() / 1000;
    const expiry = Number(rToken.getExpiryTime());
    if (expiry !== 0 && expiry < now) {
      const signedToken = rToken.getSignedToken();
      winston.error("allowAccess: Authorization denied. Token expired. now=" +
        now + " expiry=" + expiry + " token=" + signedToken);

      const tokenCache = ZPEUpdater.getRoleTokenCacheMap();
      tokenCache.del(signedToken);

      return cb('ERROR: Role Token is Expired', AccessCheckStatus.DENY_ROLETOKEN_EXPIRED);
    }

    delete params.rToken;
    params.domain = rToken.getDomain();
    params.roles = rToken.getRoles();

    return this._allowActionZPE(params, cb);
  }

  static _allowActionZPE(params, cb) {
    let action = params.action,
        domain = params.domain,
        resource = params.resource,
        roles = params.roles;
    let msgPrefix = "allowActionZPE: domain(" + domain +
      ")　resource(" + resource + ")";

    if (!roles || roles.length === 0) {
      return cb(msgPrefix + ' ERROR: No roles so access denied', AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    if (!domain) {
      return cb(msgPrefix + ' ERROR: No domain so access denied', AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    if (!action) {
      return cb(msgPrefix + ' ERROR: No action so access denied', AccessCheckStatus.DENY_INVALID_PARAMETERS);
    }

    if (!resource) {
      return cb(msgPrefix + ' ERROR: No resource so access denied', AccessCheckStatus.DENY_INVALID_PARAMETERS);
    }

    params.msgPrefix = msgPrefix;

    return this._allowActionZPEChecked(params, cb);
    }

  static _allowActionZPEChecked(params, cb) {
    let action = params.action,
        domain = params.domain,
        resource = params.resource,
        roles = params.roles,
        msgPrefix = params.msgPrefix;
    params.action = action.toLowerCase();
    params.resource = this.stripDomainPrefix(resource.toLowerCase(), domain, null);

    // Note: if domain in token doesn't match domain in resource then there
    // will be no match of any resource in the assertions - so deny immediately

    if (!params.resource) {
      let msg = msgPrefix + ' ERROR: Domain mismatch in token(' +
        domain + ') and resource so access denied';
      return cb(msg, AccessCheckStatus.DENY_DOMAIN_MISMATCH);
    }

    params.status = AccessCheckStatus.DENY_DOMAIN_NOT_FOUND;

    console.log(params);

    return this._checkDenyAssertion(params, cb);
  }

  static _checkDenyAssertion(params, cb) {
    let action = params.action,
        domain = params.domain,
        resource = params.resource,
        roles = params.roles,
        status = params.status,
        msgPrefix = params.msgPrefix;
    // first hunt by role for deny assertions since deny takes precedence
    // over allow assertions

    let roleMap = ZPEUpdater.getRoleDenyAssertions(domain);
    if (roleMap && Object.keys(roleMap).length > 0) {
      if (this._actionByRole(action, domain, resource, roles, roleMap)) {
        return cb(null, AccessCheckStatus.DENY);
      } else {
        status = AccessCheckStatus.DENY_NO_MATCH;
      }
    } else if (roleMap) {
      status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
    }

    // if the check was not explicitly denied by a standard role, then
    // let's process our wildcard roles for deny assertions

    roleMap = ZPEUpdater.getWildcardDenyAssertions(domain);
    if (roleMap && Object.keys(roleMap).length > 0) {
      if (this._actionWildcardByRole(action, domain, resource, roles, roleMap)) {
        return cb(null, AccessCheckStatus.DENY);
      } else {
        status = AccessCheckStatus.DENY_NO_MATCH;
      }
    } else if (status !== AccessCheckStatus.DENY_NO_MATCH && roleMap) {
      status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
    }

    params.status = status;

    return this._checkAllowAssertion(params, cb);
  }

  static _checkAllowAssertion(params, cb) {
    let action = params.action,
        domain = params.domain,
        resource = params.resource,
        roles = params.roles,
        status = params.status,
        msgPrefix = params.msgPrefix;

    // so far it did not match any deny assertions so now let's
    // process our allow assertions

    let roleMap = ZPEUpdater.getRoleAllowAssertions(domain);
    if (roleMap && Object.keys(roleMap).length > 0) {
      if (this._actionByRole(action, domain, resource, roles, roleMap)) {
        return cb(null, AccessCheckStatus.ALLOW);
      } else {
        status = AccessCheckStatus.DENY_NO_MATCH;
      }
    } else if (status !== AccessCheckStatus.DENY_NO_MATCH && roleMap) {
      status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
    }

    // at this point we either got an allow or didn't match anything so we're
    // going to try the wildcard roles

    roleMap = ZPEUpdater.getWildcardAllowAssertions(domain);
    if (roleMap && Object.keys(roleMap).length > 0) {
      if (this._actionWildcardByRole(action, domain, resource, roles, roleMap)) {
        return cb(null, AccessCheckStatus.ALLOW);
      } else {
        status = AccessCheckStatus.DENY_NO_MATCH;
      }
    } else if (status !== AccessCheckStatus.DENY_NO_MATCH && roleMap) {
      status = AccessCheckStatus.DENY_DOMAIN_EMPTY;
    }

    params.status = status;

    return this._checkStatus(params, cb);
  }

  static _checkStatus(params, cb) {
    let action = params.action,
        domain = params.domain,
        resource = params.resource,
        roles = params.roles,
        status = params.status,
        msgPrefix = params.msgPrefix;

    if (status === AccessCheckStatus.DENY_DOMAIN_NOT_FOUND) {
      winston.debug(msgPrefix + ": No role map found for domain=" + domain +
        " so access denied");
    } else if (status === AccessCheckStatus.DENY_DOMAIN_EMPTY) {
      winston.debug(msgPrefix + ": No policy assertions for domain=" + domain +
        " so access denied");
    }

    return cb(null, status);
  }

  static stripDomainPrefix(assertString, domain, defaultValue) {
    this.init();
    let index = assertString.indexOf(':');
    if (index === -1) {
      return assertString;
    }

    if (assertString.substring(0, index) !== domain) {
      return defaultValue;
    }

    return assertString.substring(index + 1);
  }

  static _actionByRole(action, domain, resource, roles, roleMap) {
    let msgPrefix = "allowActionByRole: domain(" + domain +
      ") action(" + action + ") resource(" + resource +")";

    for (let role of roles) {
      winston.debug(msgPrefix + ": Process role (" + role + ")");

      let asserts = roleMap[role];

      if (!asserts || asserts.length === 0) {
        winston.debug(msgPrefix + ": No policy assertions in domain=" + domain +
          " for role=" + role + " so access denied");
        continue;
      }

      if (this._matchAssertion(asserts, role, action, resource, msgPrefix)) {
        return true;
      }
    }

    return false;
  }

  static _actionWildcardByRole(action, domain, resource, roles, roleMap) {
    let msgPrefix = "allowActionByRole: domain(" + domain +
      ") action(" + action + ") resource(" + resource + ")";
    let keys = Object.keys(roleMap);

    for (let role of roles) {
      winston.debug(msgPrefix + ": Process role (" + role + ")");

      for(let roleName of keys) {
        let asserts = roleMap[roleName];

        if (!asserts || asserts.length === 0) {
          winston.debug(msgPrefix + ": No policy assertions in domain=" + domain +
            " for role=" + role + " so access denied");
          continue;
        }

        let assert = asserts[0];
        let matchStruct = assert.roleMatchStruct;
        if (!matchStruct.matches(role)) {
          const polName = assert.polName;
          winston.debug(msgPrefix + ": policy(" + polName +
              ") regexpr-match: FAILed: assert-role(" + roleName +
              ") doesnt match role(" + role + ")");
          continue;
        }

        if (this._matchAssertion(asserts, roleName, action, resource, msgPrefix)) {
          return true;
        }
      }
    }

    return false;
  }

  static _matchAssertion(asserts, role, action, resource, msgPrefix) {
    let matchStruct = null;
    for (let assert of asserts) {
      let assertAction = assert.action,
          assertResource = assert.resource,
          assertRole = assert.role,
          polname = assert.polname;

      winston.debug(msgPrefix + ": Process Assertion: policy(" + polname +
          ") assert-action=" + assertAction +
          " assert-resource=" + assertResource + " assert-role=" + assertRole);

      matchStruct = assert.actionMatchStruct;
      if (!matchStruct.matches(action)) {
        winston.debug(msgPrefix + ": policy(" + polname + ") regexpr-match: FAILed: assert-action(" +
          assertAction + ") doesn't match action(" + action + ")");
        continue;
      }

      matchStruct = assert.resourceMatchStruct;
      if (!matchStruct.matches(resource)) {
        winston.debug(msgPrefix + ": policy(" + polname + ") regexpr-match: FAILed: assert-resource(" +
          assertResource + ") doesn't match resource(" + resource + ")");
        continue;
      }

      winston.debug(msgPrefix + ": policy(" + polname + ") MATCHed: role(" + role +
        ") resource(" + resource + ") action(" + action + ")");
      return true;
    }

    return false;
  }
}

module.exports = AuthZPEClient;
