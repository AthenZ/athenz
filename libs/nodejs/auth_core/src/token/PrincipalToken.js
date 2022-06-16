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

class PrincipalToken extends Token {
    constructor(token) {
        super();

        this._name = null;
        this._originalRequestor = null;
        this._keyService = null;
        this._authorizedServices = null;
        this._authorizedServiceName = null;
        this._authorizedServiceKeyId = '0';
        this._authorizedServiceSignature = null;

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
            'Constructing PrincipalToken with input string: ' + signedToken
        );

        if (!signedToken) {
            throw new Error('Input String signedToken must not be empty');
        }

        /**
         * first we need to extract data and signature parts
         * the signature is always at the end of the token. The principal
         * token can represent 2 types - service or user. The version
         * string identifies the type by using S or U. Here are two sample
         * tokens:
         *
         * User:
         * v=U1;d=user;n=john;a=salt;t=tstamp;e=expiry;s=sig
         *
         * Service:
         * v=S1;d=sports;n=storage;h=host.somecompany.com;a=salt;t=tstamp;e=expiry;s=sig
         *
         * v: version number U1 or S1 (string)
         * d: domain name (as passed by the client) or user for users
         * n: service name (as passed by the client) or username
         * h: hostname or IP address (string)
         * a: random 8 byte salt value hex encoded
         * t: timestamp when the token was generated
         * e: expiry timestamp based on SIA configuration
         * s: signature generated over the "v=U1;a=salt;...;e=expiry" string
         *    using Service's private Key for service tokens and ZMS service's
         *    private key for user tokens and y64 encoded
         */
        var idx = signedToken.indexOf(';s=');
        if (idx !== -1) {
            this._unsignedToken = signedToken.substring(0, idx);
        }

        var item = signedToken.split(';');
        for (var i = 0; i < item.length; i++) {
            var kv = item[i].split('=');
            if (kv.length === 2) {
                switch (kv[0]) {
                    case 'a':
                        this._salt = kv[1];
                        break;
                    case 'b':
                        this._authorizedServices = kv[1].split(',');
                        break;
                    case 'bk':
                        this._authorizedServiceKeyId = kv[1];
                        break;
                    case 'bn':
                        this._authorizedServiceName = kv[1];
                        break;
                    case 'bs':
                        this._authorizedServiceSignature = kv[1];
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
                    case 'n':
                        this._name = kv[1];
                        break;
                    case 'o':
                        this._originalRequestor = kv[1];
                        break;
                    case 's':
                        this._signature = kv[1];
                        break;
                    case 't':
                        this._timestamp = Number(kv[1]);
                        break;
                    case 'v':
                        this._version = kv[1];
                        break;
                    case 'z':
                        this._keyService = kv[1];
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

        if (!this._name) {
            throw new Error(
                'SignedToken does not contain required name component'
            );
        }

        this._signedToken = signedToken;

        logger.debug(
            'Values extracted from token ' +
                ' version:' +
                this._version +
                ' domain:' +
                this._domain +
                ' service:' +
                this._name +
                ' host:' +
                this._host +
                ' ip: ' +
                this._ip +
                ' id: ' +
                this._keyId +
                ' keyService: ' +
                this._keyService +
                ' originalRequestor: ' +
                this._originalRequestor +
                ' salt:' +
                this._salt +
                ' timestamp:' +
                this._timestamp +
                ' expiryTime:' +
                this._expiryTime +
                ' signature:' +
                this._signature
        );
        if (this._authorizedServices) {
            logger.debug(
                'Authorized service details from token ' +
                    ' authorizedServices:' +
                    this._authorizedServices.join(',') +
                    ' authorizedServiceName:' +
                    this._authorizedServiceName +
                    ' authorizedServiceKeyId:' +
                    this._authorizedServiceKeyId +
                    ' authorizedServiceSignature:' +
                    this._authorizedServiceSignature
            );
        }
    }

    builder(options) {
        if (!options.version || !options.domain || !options.name) {
            throw new Error(
                'version, domain and name parameters must not be null.'
            );
        }

        this._version = options.version;
        this._domain = options.domain;
        this._name = options.name;
        this._host = options.host;
        this._salt = options.salt || Crypto.randomSalt();
        this._keyId = options.keyId || '0';
        this._ip = options.ip;
        this._authorizedServices = options.authorizedServices
            ? options.authorizedServices.split(',')
            : null;
        this._keyService = options.keyService;
        this._originalRequestor = options.originalRequestor;

        this.setTimeStamp(
            options.issueTime || 0,
            options.expirationWindow || 3600
        );

        var parts = [];
        parts.push('v=' + this._version);
        parts.push('d=' + this._domain);
        parts.push('n=' + this._name);
        if (this._host) {
            parts.push('h=' + this._host);
        }
        parts.push('a=' + this._salt);
        parts.push('t=' + this._timestamp);
        parts.push('e=' + this._expiryTime);
        parts.push('k=' + this._keyId);
        if (this._keyService) {
            parts.push('z=' + this._keyService);
        }
        if (this._originalRequestor) {
            parts.push('o=' + this._originalRequestor);
        }
        if (this._ip) {
            parts.push('i=' + this._ip);
        }
        if (this._authorizedServices) {
            parts.push('b=' + this._authorizedServices.join(','));
        }
        this._unsignedToken = parts.join(';');
        logger.debug('PrincipalToken created: ' + this._unsignedToken);
    }

    signForAuthorizedService(
        authorizedServiceName,
        authorizedServiceKeyId,
        privateKey
    ) {
        /* first let's make sure the authorized service is one of the
         * listed service names in the PrincipalToken */
        if (
            !this._authorizedServices ||
            this._authorizedServices.indexOf(authorizedServiceName) === -1
        ) {
            throw new Error('Authorized Service is not valid for this token');
        }

        this._authorizedServiceKeyId = authorizedServiceKeyId;
        var tokenToSign = this._signedToken + ';bk=' + authorizedServiceKeyId;

        if (this._authorizedServices.length > 1) {
            /* if the user has allowed multiple authorized services then we need
             * to keep track of which one is re-signing this._token and as such
             * we'll store the service name as the value for the bn field */
            this._authorizedServiceName = authorizedServiceName;
            tokenToSign += ';bn=' + authorizedServiceName;
        }

        this._authorizedServiceSignature = Crypto.sign(
            tokenToSign,
            privateKey,
            this._digestAlgorithm
        );

        /* now append our new signature to the token we just signed */
        tokenToSign += ';bs=' + this._authorizedServiceSignature;
        this._signedToken = tokenToSign;
    }

    validateForAuthorizedService(publicKey) {
        var err = null;
        if (!this._authorizedServiceSignature) {
            err = new Error(
                'PrincipalToken:validateForAuthorizedService: token=' +
                    this._unsignedToken +
                    ' : missing data/signature component: public key=' +
                    publicKey
            );
            logger.error(err);
            return false;
        }

        var idx = this._signedToken.indexOf(';bs=');
        if (idx === -1) {
            err = new Error(
                'PrincipalToken:validateForAuthorizedService: token=' +
                    this._unsignedToken +
                    ' : not signed by any authorized service'
            );
            logger.error(err);
            return false;
        }

        var unsignedAuthorizedServiceToken = this._signedToken.substring(
            0,
            idx
        );
        if (!publicKey) {
            err = new Error(
                'PrincipalToken:validateForAuthorizedService: token=' +
                    this._unsignedToken +
                    ' : No public key provided'
            );
            logger.error(err);
            return false;
        }

        var verified = false; // fail safe
        try {
            verified = Crypto.verify(
                unsignedAuthorizedServiceToken,
                publicKey,
                this._authorizedServiceSignature,
                this._digestAlgorithm
            );
            if (verified === false) {
                err = new Error(
                    'PrincipalToken:validateForAuthorizedService: token=' +
                        this._unsignedToken +
                        ' : authentication failed: public key=' +
                        publicKey
                );
                logger.error(err);
            }
            logger.debug(
                'PrincipalToken:validateForAuthorizedService: token=' +
                    this._unsignedToken +
                    ' -  successfully authenticated'
            );
        } catch (e) {
            logger.error(
                'PrincipalToken:validateForAuthorizedService: token=' +
                    this._unsignedToken +
                    ' : authentication failed verifying signature: exc=' +
                    e.message +
                    ' : public key=' +
                    publicKey
            );
        }
        return verified;
    }

    isValidAuthorizedServiceToken() {
        var err = null;

        /* we start our by checking if this is an authorized service token */
        if (!this._authorizedServices) {
            /* if both the service name list and signature are not present
             * then we have a standard principal token */
            if (!this._authorizedServiceSignature) {
                return true;
            }

            /* otherwise we have an invalid token without the signature */
            err = new Error(
                'PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=' +
                    this._unsignedToken +
                    ' : Authorized Service Signature available without service name'
            );
            logger.error(err);
            return false;
        }

        /* if we have an authorized service name then we must have a corresponding
         * signature available in the token */
        if (!this._authorizedServiceSignature) {
            err = new Error(
                'PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=' +
                    this._unsignedToken +
                    ' : Missing signature for specified authorized service'
            );
            logger.error(err);
            return false;
        }

        /* if we have a specific authorized service name specified then
         * it must be present in our service list otherwise we must
         * have a single entry in our list */
        if (this._authorizedServiceName) {
            if (
                this._authorizedServices.indexOf(
                    this._authorizedServiceName
                ) === -1
            ) {
                err = new Error(
                    'PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=' +
                        this._unsignedToken +
                        ' : Authorized service name=' +
                        this._authorizedServiceName +
                        ' is not listed in the service list'
                );
                logger.error(err);
                return false;
            }
        } else if (this._authorizedServices.length !== 1) {
            err = new Error(
                'PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=' +
                    this._unsignedToken +
                    ' : No service name and Authorized service list contains multiple entries'
            );
            logger.error(err);
            return false;
        }

        return true;
    }

    getName() {
        return this._name;
    }

    getKeyService() {
        return this._keyService;
    }

    getOriginalRequestor() {
        return this._originalRequestor;
    }

    getAuthorizedServices() {
        return this._authorizedServices;
    }

    getAuthorizedServiceName() {
        return this._authorizedServiceName;
    }

    getAuthorizedServiceKeyId() {
        return this._authorizedServiceKeyId;
    }

    getAuthorizedServiceSignature() {
        return this._authorizedServiceSignature;
    }
}

module.exports = PrincipalToken;
