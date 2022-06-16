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
var PrincipalToken = require('../token/PrincipalToken');
var SimplePrincipal = require('./SimplePrincipal');
var config = require('../../config/config')();

var USER_DOMAIN = 'user';
var SYS_AUTH_DOMAIN = 'sys.auth';
var ZMS_SERVICE = 'zms';
var ZTS_SERVICE = 'zts';

var ATHENZ_PROP_TOKEN_OFFSET;
var ATHENZ_PROP_IP_CHECK_MODE;
var ATHENZ_PROP_USER_DOMAIN;
var ATHENZ_PROP_PRINCIPAL_HEADER;

class PrincipalAuthority {
    constructor() {
        ATHENZ_PROP_TOKEN_OFFSET = Number(config.principalTokenAllowedOffset);
        ATHENZ_PROP_IP_CHECK_MODE = config.principalIpCheckMode;
        ATHENZ_PROP_USER_DOMAIN = config.principalUserDomain;
        ATHENZ_PROP_PRINCIPAL_HEADER = config.principalHeader;

        this._keyStore = null;
        this._allowedOffset = ATHENZ_PROP_TOKEN_OFFSET
            ? Number(ATHENZ_PROP_TOKEN_OFFSET)
            : 300;
        this._ipCheckMode = ATHENZ_PROP_IP_CHECK_MODE || 'OPS_WRITE';
        this._userDomain = ATHENZ_PROP_USER_DOMAIN || 'user';
        this._headerName =
            ATHENZ_PROP_PRINCIPAL_HEADER || 'Athenz-Principal-Auth';

        // case of invalid value, we'll default back to 5 minutes
        if (this._allowedOffset < 0) {
            this._allowedOffset = 300;
        }
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.auth_core);
        PrincipalToken.setConfig(c);
        SimplePrincipal.setConfig(c);
    }

    initialize() {}

    getDomain() {
        return null;
    }

    getHeader() {
        return this._headerName;
    }

    authenticate(signedToken, remoteAddr, httpMethod) {
        logger.debug('Authenticating PrincipalToken: ' + signedToken);

        var serviceToken = null;
        try {
            serviceToken = new PrincipalToken(signedToken);
        } catch (e) {
            logger.error(
                'PrincipalAuthority:authenticate: Invalid token: exc=' +
                    e.message +
                    ' : credential=' +
                    PrincipalToken.getUnsignedToken(signedToken)
            );
            return null;
        }

        /* before authenticating verify that if this is a valid
         * authorized service token or not and if required
         * components are provided (the method already logs
         * all error messages) */
        if (!serviceToken.isValidAuthorizedServiceToken()) {
            logger.error(
                'PrincipalAuthority:authenticate: Invalid authorized service token: credential=' +
                    PrincipalToken.getUnsignedToken(signedToken)
            );
            return null;
        }

        var tokenDomain = serviceToken.getDomain().toString().toLowerCase();
        var tokenName = serviceToken.getName().toString().toLowerCase();
        var keyService = serviceToken.getKeyService();
        var userToken = tokenDomain === this._userDomain;

        /* get the public key for this token to validate signature */
        var publicKey = this._getPublicKey(
            tokenDomain,
            tokenName,
            keyService,
            serviceToken.getKeyId(),
            userToken
        );

        /* the validate method logs all error messages */
        var writeOp = this._isWriteOperation(httpMethod);
        if (
            serviceToken.validate(publicKey, this._allowedOffset, !writeOp) ===
            false
        ) {
            logger.error(
                'PrincipalAuthority:authenticate: service token validation failure: credential=' +
                    PrincipalToken.getUnsignedToken(signedToken)
            );
            return null;
        }

        /* if an authorized service signature is available then we're going to validate
         * that signature as well to support token chaining in Athenz and, if necessary,
         * bypass IP address mismatch for users */
        var authorizedServiceName = null;
        if (serviceToken.getAuthorizedServiceSignature()) {
            authorizedServiceName =
                this._validateAuthorizeService(serviceToken);
            if (!authorizedServiceName) {
                logger.error(
                    'PrincipalAuthority:authenticate: validation of authorized service failure: credential=' +
                        PrincipalToken.getUnsignedToken(signedToken)
                );
                return null;
            }
        }

        /* if we have a usertoken and our remote ip check enabled, verify that the IP address
         * matches before allowing the operation go through */
        if (
            userToken &&
            !this._remoteIpCheck(
                remoteAddr,
                writeOp,
                serviceToken,
                authorizedServiceName
            )
        ) {
            logger.error(
                'PrincipalAuthority:authenticate: IP Mismatch - token (' +
                    serviceToken.getIP() +
                    ') request (' +
                    remoteAddr +
                    ')'
            );
            return null;
        }

        /* all the role members in Athenz are normalized to lower case so we need to make
         * sure our principal's name and domain are created with lower case as well */
        var princ = SimplePrincipal.createByUserIdentity(
            tokenDomain,
            tokenName,
            signedToken,
            serviceToken.getTimestamp(),
            this
        );
        princ.setUnsignedCreds(serviceToken.getUnsignedToken());
        princ.setAuthorizedService(authorizedServiceName);
        princ.setOriginalRequestor(serviceToken.getOriginalRequestor());
        princ.setKeyService(keyService);
        princ.setIP(serviceToken.getIP());
        princ.setKeyId(serviceToken.getKeyId());
        return princ;
    }

    _remoteIpCheck(remoteAddr, writeOp, serviceToken, authorizedServiceName) {
        var checkResult = true;
        switch (this._ipCheckMode) {
            case 'OPS_ALL':
                if (remoteAddr !== serviceToken.getIP()) {
                    checkResult = false;
                }
                break;
            case 'OPS_WRITE':
                /* if we have a user token for a write operation and we have an IP address
                 * mismatch then we'll allow this authenticate request to proceed only if it's
                 * been configured with authorized user only. */
                if (writeOp && remoteAddr !== serviceToken.getIP()) {
                    if (!authorizedServiceName) {
                        checkResult = false;
                    }
                }
                break;
            case 'OPS_NONE':
                break;
            default:
                checkResult = false;
                break;
        }
        return checkResult;
    }

    _getPublicKey(tokenDomain, tokenName, keyService, keyId, userToken) {
        /* by default we're going to look for the public key for the domain
         * and service defined in the token */
        var publicKeyDomain = tokenDomain;
        var publicKeyService = tokenName;

        /* now let's handle the exceptions:
         * 1) if the token has a key service field set then only supported values are
         * either zms or zts, so we use sys.auth.zms or sys.auth.zts services
         * 2) if the token's domain is user then it's a user token or if it's sd then
         * it's our special project token so for those cases we are going to ask for
         * zms's own public key. */
        if (keyService) {
            if (keyService === ZMS_SERVICE) {
                publicKeyDomain = SYS_AUTH_DOMAIN;
                publicKeyService = ZMS_SERVICE;
            } else if (keyService === ZTS_SERVICE) {
                publicKeyDomain = SYS_AUTH_DOMAIN;
                publicKeyService = ZTS_SERVICE;
            }
        } else if (userToken) {
            publicKeyDomain = SYS_AUTH_DOMAIN;
            publicKeyService = ZMS_SERVICE;
        }

        return this._keyStore.getPublicKey(
            publicKeyDomain,
            publicKeyService,
            keyId
        );
    }

    _isWriteOperation(httpMethod) {
        if (!httpMethod) {
            return false;
        }
        if (
            httpMethod.toString().toUpperCase() === 'PUT' ||
            httpMethod.toString().toUpperCase() === 'POST' ||
            httpMethod.toString().toUpperCase() === 'DELETE'
        ) {
            return true;
        } else {
            return false;
        }
    }

    _getAuthorizedServiceName(authorizedServices, authorizedServiceName) {
        /* if we have an authorized service name specified then it must be
         * present in the authorized services list or if it's null then the
         * list must contain a single element only */
        var serviceName = authorizedServiceName;
        var err = null;
        if (!serviceName) {
            if (authorizedServices.length !== 1) {
                logger.error(
                    'getAuthorizedServiceName() failed: No authorized service name specified'
                );
                return null;
            }
            serviceName = authorizedServices[0];
        } else {
            if (authorizedServices.indexOf(serviceName) === -1) {
                logger.error(
                    'getAuthorizedServiceName() failed: Invalid authorized service name specified:' +
                        serviceName
                );
                return null;
            }
        }
        return serviceName;
    }

    _validateAuthorizeService(userToken) {
        /* if we have an authorized service name specified then it must be
         * present in the authorized services list or if it's null then the
         * list must contain a single element only */
        var authorizedServiceName = userToken.getAuthorizedServiceName();
        var err = null;
        if (!authorizedServiceName) {
            var authorizedServices = userToken.getAuthorizedServices();
            if (!authorizedServices || authorizedServices.length !== 1) {
                logger.error(
                    'PrincipalAuthority:validateAuthorizeService: ' +
                        'No service name and services list empty OR contains multiple entries: token=' +
                        userToken.getUnsignedToken()
                );
                return null;
            } else {
                authorizedServiceName = authorizedServices[0];
            }
        }

        /* need to extract domain and service name from our full service name value */
        var idx = authorizedServiceName.lastIndexOf('.');
        if (idx <= 0 || idx === authorizedServiceName.length - 1) {
            logger.error(
                'PrincipalAuthority:validateAuthorizeService: ' +
                    'failed: token=' +
                    userToken.getUnsignedToken() +
                    ' : Invalid authorized service name specified=' +
                    authorizedServiceName
            );
            return null;
        }

        var publicKey = this._keyStore.getPublicKey(
            authorizedServiceName.substring(0, idx),
            authorizedServiceName.substring(idx + 1),
            userToken.getAuthorizedServiceKeyId()
        );

        /* the token method reports all error messages */
        if (!userToken.validateForAuthorizedService(publicKey)) {
            logger.error(
                'PrincipalAuthority:validateAuthorizeService: token validation for authorized service failed'
            );
            return null;
        }
        return authorizedServiceName;
    }

    setKeyStore(keyStore) {
        this._keyStore = keyStore;
    }
}

module.exports = PrincipalAuthority;
