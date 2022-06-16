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
var Token = require('./Token');
var Crypto = require('../util/Crypto');
var config = require('../../config/config')();

class RoleToken extends Token {
    constructor(token) {
        super();

        this._roles = null;
        this._principal = null;
        this._proxyUser = null;
        this._domainCompleteRoleSet = null;

        if (typeof token === 'string') {
            try {
                this.parseSignedToken(token);
            } catch (e) {
                throw e;
            }
        } else {
            try {
                this.builder(token);
            } catch (e) {
                throw e;
            }
        }
    }

    static setConfig(c) {
        super.setConfig(c);
        config = Object.assign({}, config, c.auth_core);
    }

    /*eslint complexity: ["error", 24]*/
    parseSignedToken(signedToken) {
        logger.debug(
            'Constructing RoleToken with input string: ' + signedToken
        );

        if (!signedToken) {
            throw new Error('Input String signedToken must not be empty');
        }

        /**
         * first we need to extract data and signature parts
         * the signature is always at the end of the token.
         * The format for the Token is as follows:
         *
         * v=Z1;d=sports;r=role1,role2;a=salt;t=tstamp;e=expiry;k=1;s=sig
         *
         * v: version number Z1 (string)
         * d: domain name where the roles are valid for
         * r: list of comma separated roles
         * c: the list of roles is complete in domain
         * p: principal that got the token issued for
         * a: random 8 byte salt value hex encoded
         * t: timestamp when the token was generated
         * h: host that issued this role token
         * e: expiry timestamp based on SIA configuration
         * k: identifier - either version or zone name
         * s: signature generated over the "v=Z1;a=salt;...;e=expiry" string
         *    using Service's private Key and y64 encoded
         * proxy: request was done by this authorized proxy user
         */
        var idx = signedToken.indexOf(';s=');
        if (idx !== -1) {
            this._unsignedToken = signedToken.substring(0, idx);
        }

        var roleNames = null;
        var item = signedToken.split(';');
        for (var i = 0; i < item.length; i++) {
            var kv = item[i].split('=');
            if (kv.length === 2) {
                switch (kv[0]) {
                    case 'a':
                        this._salt = kv[1];
                        break;
                    case 'c':
                        if (Number(kv[1]) === 1) {
                            this._domainCompleteRoleSet = true;
                        }
                        break;
                    case 'd':
                        this._domain = kv[1];
                        break;
                    case 'e':
                        this._expiryTime = Number(kv[1]);
                        break;
                    case 'h':
                        this._host = kv[1];
                        break;
                    case 'i':
                        this._ip = kv[1];
                        break;
                    case 'k':
                        this._keyId = kv[1];
                        break;
                    case 'p':
                        this._principal = kv[1];
                        break;
                    case 'r':
                        roleNames = kv[1];
                        break;
                    case 's':
                        this._signature = kv[1];
                        break;
                    case 't':
                        this._timestamp = Number(kv[1]);
                        break;
                    case 'proxy':
                        this._proxyUser = kv[1];
                        break;
                    case 'v':
                        this._version = kv[1];
                        break;
                }
            }
        }

        /* the required attributes for the token are
         * domain and roles. The signature will be verified
         * during the authenticate phase but now we'll make
         * sure that domain and roles are present
         */

        if (!this._domain) {
            throw new Error(
                'SignedToken does not contain required domain component'
            );
        }

        if (!roleNames) {
            throw new Error(
                'SignedToken does not contain required roles component'
            );
        }

        this._roles = roleNames.split(',');

        this._signedToken = signedToken;

        logger.debug(
            'Values extracted from token ' +
                ' version:' +
                this._version +
                ' domain:' +
                this._domain +
                ' roles:' +
                roleNames +
                ' principal:' +
                this._principal +
                ' host:' +
                this._host +
                ' salt:' +
                this._salt +
                ' timestamp:' +
                this._timestamp +
                ' expiryTime:' +
                this._expiryTime +
                ' domainCompleteRoleSet: ' +
                this.domainCompleteRoleSet +
                ' keyId: ' +
                this._keyId +
                ' ip: ' +
                this._ip +
                ' proxyUser: ' +
                this._proxyUser +
                ' signature:' +
                this._signature
        );
    }

    builder(options) {
        if (!options.version || !options.domain || !options.roles) {
            throw new Error(
                'version, domain and roles parameters must not be null.'
            );
        }

        if (
            options.version.length === 0 ||
            options.domain.length === 0 ||
            options.roles.length === 0
        ) {
            throw new Error(
                'version, domain and roles parameters must have values.'
            );
        }

        // required attributes
        this._version = options.version;
        this._domain = options.domain;
        this._roles = options.roles;
        this._principal = options.principal;
        this._proxyUser = options.proxyUser;
        this._domainCompleteRoleSet = options.domainCompleteRoleSet || false;

        // optional attributes with default values
        this._salt = options.salt || Crypto.randomSalt();
        this._host = options.host;
        this._ip = options.ip;
        this._keyId = options.keyId || '0';

        this.setTimeStamp(
            options.issueTime || 0,
            options.expirationWindow || 3600
        );

        var parts = [];
        parts.push('v=' + this._version);
        parts.push('d=' + this._domain);
        parts.push('r=' + this._roles.join(','));
        if (this._domainCompleteRoleSet) {
            parts.push('c=1');
        }
        if (this._principal) {
            parts.push('p=' + this._principal);
        }
        if (this._host) {
            parts.push('h=' + this._host);
        }
        if (this._proxyUser) {
            parts.push('proxy=' + this._proxyUser);
        }
        parts.push('a=' + this._salt);
        parts.push('t=' + this._timestamp);
        parts.push('e=' + this._expiryTime);
        parts.push('k=' + this._keyId);
        if (this._ip) {
            parts.push('i=' + this._ip);
        }
        this._unsignedToken = parts.join(';');
        logger.debug('RoleToken created: ' + this._unsignedToken);
    }

    getPrincipal() {
        return this._principal;
    }

    getRoles() {
        return this._roles;
    }

    getProxyUser() {
        return this._proxyUser;
    }

    getDomainCompleteRoleSet() {
        return this._domainCompleteRoleSet;
    }
}

module.exports = RoleToken;
