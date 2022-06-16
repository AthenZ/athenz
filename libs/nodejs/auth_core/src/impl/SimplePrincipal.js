/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const logger = require('../../logger');
var Validate = require('../util/Validate');
var config = require('../../config/config')();

class SimplePrincipal {
    /*eslint max-params: ["error", 6]*/
    constructor(domain, name, creds, roles, issueTime, authority) {
        this._domain = domain;
        this._name = name;
        this._creds = creds;
        this._roles = roles;
        this._issueTime = Number(issueTime);
        this._authority = authority;
        this._fullName = null;
        this._unsignedCreds = null;
        this._ip = null;
        this._authorizedService = null;
        this._originalRequestor = null;
        this._keyService = null;
        this._keyId = null;
        this._x509Certificate = null;
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.auth_core);
    }

    static _simplePrincipal(domain, name, creds, issueTime, authority) {
        return new SimplePrincipal(
            domain,
            name,
            creds,
            null,
            issueTime,
            authority
        );
    }

    static _simplePrincipalByRoles(domain, creds, roles, authority) {
        return new SimplePrincipal(domain, null, creds, roles, 0, authority);
    }

    static create(domain, name, creds) {
        return this.createByUserIdentity(domain, name, creds, 0, null);
    }

    /**
     * Create a Principal based on a given RoleToken
     * @param domain Domain name that the RoleToken was issued for
     * @param creds Credentials of the principal (RoleToken)
     * @param roles List of roles defined in the token
     * @param authority authority responsible for the credentials (RoleAuthority)
     * @return a Principal for the given set of roles in a domain
     */
    static createByRoles(domain, creds, roles, authority) {
        if (!Validate.domainName(domain)) {
            logger.warn('createByRoles: failed to validate domain ' + domain);
        }

        if (!roles || roles.length === 0) {
            logger.warn('zero roles: ' + creds);
        }

        return this._simplePrincipalByRoles(domain, creds, roles, authority);
    }

    /**
     * Create a Principal for the given identity
     * @param domain Domain name for the identity
     * @param name Name of the identity
     * @param creds Credentials of the principal (PrincipalToken which could be either UserToken or ServiceToken)
     * @param authority authority responsible for the credentials (e.g. PrincipalAuthority)
     * @return a Principal for the identity
     */
    static createByIdentity(domain, name, creds, authority) {
        return this.createByUserIdentity(domain, name, creds, '0', authority);
    }

    /**
     * Create a Principal for the given user identity
     * @param domain Domain name for the identity (For users this will always be user)
     * @param name Name of the identity
     * @param creds Credentials of the principal (e.g. Cookie.User)
     * @param issueTime when the User Cookie/Credentials was issued
     * @param authority authority responsible for the credentials (e.g. UserAuthority)
     * @return a Principal for the identity
     */
    static createByUserIdentity(domain, name, creds, issueTime, authority) {
        if (!Validate.domainName(domain)) {
            logger.warn(
                'createByUserIdentity: failed to validate domain ' + domain
            );
        }

        if (!Validate.principalName(name)) {
            logger.warn(
                'createByUserIdentity: failed to validate name ' + name
            );
        }

        if (domain) {
            var matchDomain = !authority ? null : authority.getDomain();
            if (matchDomain && domain !== matchDomain) {
                logger.warn(
                    'domain mismatch for user ' +
                        name +
                        ' in authority + ' +
                        authority
                );
                return null;
            }
        } else if (authority) {
            if (authority.getDomain()) {
                logger.warn(
                    'domain mismatch for user ' +
                        name +
                        ' in authority + ' +
                        authority
                );
                return null;
            }
        }

        return this._simplePrincipal(domain, name, creds, issueTime, authority);
    }

    /**
     * Create a Principal for the given host identity
     * @param appId Application identifer
     * @param creds Credentials of the principal
     * @param authority authority responsible for the credentials (e.g. HostAuthority)
     * @return a Principal for the host identity
     */
    static createByHostIdentity(appId, creds, authority) {
        return this._simplePrincipal(null, appId, creds, 0, authority);
    }

    setUnsignedCreds(unsignedCreds) {
        this._unsignedCreds = unsignedCreds;
    }

    setAuthorizedService(authorizedService) {
        this._authorizedService = authorizedService;
    }

    setIP(ip) {
        this._ip = ip;
    }

    setOriginalRequestor(originalRequestor) {
        this._originalRequestor = originalRequestor;
    }

    setKeyService(keyService) {
        this._keyService = keyService;
    }

    setKeyId(keyId) {
        this._keyId = keyId;
    }

    setX509Certificate(x509Certificate) {
        this._x509Certificate = x509Certificate;
    }

    getIP() {
        return this._ip;
    }

    getUnsignedCreds() {
        return this._unsignedCreds;
    }

    getAuthority() {
        return this._authority;
    }

    getDomain() {
        return this._domain;
    }

    getName() {
        return this._name;
    }

    getOriginalRequestor() {
        return this._originalRequestor;
    }

    getFullName() {
        if (!this._fullName) {
            if (this._domain && this._name) {
                this._fullName = this._domain + '.' + this._name;
            } else if (this._domain) {
                this._fullName = this._domain;
            } else if (this._name) {
                this._fullName = this._name;
            }
        }
        return this._fullName;
    }

    getCredentials() {
        return this._creds;
    }

    getRoles() {
        return this._roles;
    }

    getIssueTime() {
        return this._issueTime;
    }

    toString() {
        if (!this._roles) {
            return this._domain + '.' + this._name;
        } else {
            return (
                'ZToken_' +
                this._domain +
                '~' +
                this._roles.toString().replace('[', '').replace(']', '')
            );
        }
    }

    getAuthorizedService() {
        return this._authorizedService;
    }

    getKeyService() {
        return this._keyService;
    }

    getKeyId() {
        return this._keyId;
    }

    getX509Certificate() {
        return this._x509Certificate;
    }
}

module.exports = SimplePrincipal;
