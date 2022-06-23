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
var Crypto = require('../util/Crypto');
var config = require('../../config/config')();

var ATHENZ_TOKEN_MAX_EXPIRY;
var ATHENZ_TOKEN_NO_EXPIRY;

class Token {
    constructor() {
        ATHENZ_TOKEN_MAX_EXPIRY =
            Number(config.tokenMaxExpiry) > 30 * 24 * 60 * 60
                ? 30 * 24 * 60 * 60
                : Number(config.tokenMaxExpiry);
        ATHENZ_TOKEN_NO_EXPIRY = config.tokenNoExpiry;

        this._unsignedToken = null;
        this._signedToken = null;
        this._version = null;
        this._salt = null;
        this._host = null;
        this._ip = null;
        this._domain = null;
        this._signature = null;
        this._keyId = '0';
        this._expiryTime = 0;
        this._timestamp = 0;
        this._digestAlgorithm = 'SHA256';
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.auth_core);
    }

    sign(privateKey) {
        try {
            this._signature = Crypto.sign(
                this._unsignedToken,
                privateKey,
                this._digestAlgorithm
            );
            this._signedToken = this._unsignedToken + ';s=' + this._signature;
        } catch (e) {
            throw e;
        }
    }

    setTimeStamp(issueTime, expirationWindow) {
        this._timestamp =
            issueTime > 0 ? issueTime : Math.floor(Date.now() / 1000);
        this._expiryTime = this._timestamp + expirationWindow;
    }

    /*eslint complexity: ["error", 12]*/
    validate(publicKey, allowedOffset, allowNoExpiry) {
        var err = null;
        if (!this._unsignedToken || !this._signature) {
            err = new Error(
                'Token:validate: token=' +
                    this._unsignedToken +
                    ' : missing data/signature component'
            );
            logger.error(err);
            return false;
        }

        if (!publicKey) {
            err = new Error(
                'Token:validate: token=' +
                    this._unsignedToken +
                    ' : No public key provided'
            );
            logger.error(err);
            return false;
        }

        var now = Math.floor(Date.now() / 1000);

        /* make sure the token does not have a timestamp in the future
         * we'll allow the configured offset between servers */
        if (this._timestamp !== 0 && this._timestamp - allowedOffset > now) {
            err = new Error(
                'Token:validate: token=' +
                    this._unsignedToken +
                    ' : has future timestamp=' +
                    this._timestamp +
                    ' : current time=' +
                    now +
                    ' : allowed offset=' +
                    allowedOffset
            );
            logger.error(err);
            return false;
        }

        /* make sure we don't have unlimited tokens unless we have
         * explicitly enabled that option for our system. by default
         * they should have an expiration date of less than 30 days */
        if (
            this._expiryTime !== 0 ||
            !ATHENZ_TOKEN_NO_EXPIRY ||
            !allowNoExpiry
        ) {
            if (this._expiryTime < now) {
                err = new Error(
                    'Token:validate: token=' +
                        this._unsignedToken +
                        ' : has expired time=' +
                        this._expiryTime +
                        ' : current time=' +
                        now
                );
                logger.error(err);
                return false;
            }
            if (
                this._expiryTime >
                now + ATHENZ_TOKEN_MAX_EXPIRY + allowedOffset
            ) {
                err = new Error(
                    'Token:validate: token=' +
                        this._unsignedToken +
                        ' : expires too far in the future=' +
                        this._expiryTime +
                        ' : current time=' +
                        now +
                        ' : max expiry=' +
                        ATHENZ_TOKEN_MAX_EXPIRY +
                        ' : allowed offset=' +
                        allowedOffset
                );
                logger.error(err);
                return false;
            }
        }

        var verified = false; //fail safe
        try {
            verified = Crypto.verify(
                this._unsignedToken,
                publicKey,
                this._signature,
                this._digestAlgorithm
            );
            if (verified === false) {
                err = new Error(
                    'Token:validate: token=' +
                        this._unsignedToken +
                        ' : authentication failed'
                );
                logger.error(err);
            } else {
                logger.debug('validate: Token successfully authenticated');
            }
        } catch (e) {
            logger.error(
                'Token:validate: token=' +
                    this._unsignedToken +
                    ' : verify signature failed due to Exception=' +
                    e.message
            );
        }

        return verified;
    }

    getVersion() {
        return this._version;
    }

    getSalt() {
        return this._salt;
    }

    getHost() {
        return this._host;
    }

    getDomain() {
        return this._domain;
    }

    getSignature() {
        return this._signature;
    }

    getTimestamp() {
        return this._timestamp;
    }

    getExpiryTime() {
        return this._expiryTime;
    }

    getSignedToken() {
        return this._signedToken;
    }

    getKeyId() {
        return this._keyId;
    }

    getIP() {
        return this._ip;
    }

    getUnsignedToken() {
        return this._unsignedToken;
    }

    /**
     * Helper method to parse a credential to remove the signature from the
     * raw credential string. Returning the unsigned credential.
     * @param credential full token credentials including signature
     * @return credentials without the signature
     **/
    static getUnsignedToken(credential) {
        if (credential) {
            var idx = credential.indexOf(';s=');
            if (idx !== -1) {
                credential = credential.substring(0, idx);
            }
        }

        return credential;
    }
}

module.exports = Token;
