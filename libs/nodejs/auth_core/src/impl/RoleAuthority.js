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
var RoleToken = require('../token/RoleToken');
var SimplePrincipal = require('./SimplePrincipal');
var config = require('../../config/config')();

var USER_DOMAIN = 'user';
var SYS_AUTH_DOMAIN = 'sys.auth';
var ZTS_SERVICE = 'zts';

var ATHENZ_PROP_TOKEN_OFFSET;
var ATHENZ_PROP_USER_DOMAIN;
var ATHENZ_PROP_ROLE_HEADER;

class RoleAuthority {
    constructor() {
        ATHENZ_PROP_TOKEN_OFFSET = Number(config.roleTokenAllowedOffset);
        ATHENZ_PROP_USER_DOMAIN = config.roleUserDomain;
        ATHENZ_PROP_ROLE_HEADER = config.roleHeader;

        this._keyStore = null;
        this._allowedOffset = ATHENZ_PROP_TOKEN_OFFSET
            ? Number(ATHENZ_PROP_TOKEN_OFFSET)
            : 300;
        this._userDomain = ATHENZ_PROP_USER_DOMAIN || 'user';
        this._headerName = ATHENZ_PROP_ROLE_HEADER || 'Athenz-Role-Auth';

        // case of invalid value, we'll default back to 5 minutes
        if (this._allowedOffset < 0) {
            this._allowedOffset = 300;
        }
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.auth_core);
        RoleToken.setConfig(c);
        SimplePrincipal.setConfig(c);
    }

    initialize() {}

    getDomain() {
        return 'sys.auth';
    }

    getHeader() {
        return this._headerName;
    }

    authenticate(signedToken, remoteAddr, httpMethod) {
        logger.debug('Authenticating PrincipalToken: ' + signedToken);

        var roleToken = null;
        try {
            roleToken = new RoleToken(signedToken);
        } catch (e) {
            logger.error(
                'PrincipalAuthority:authenticate: Invalid token: exc=' +
                    e.message +
                    ' : credential=' +
                    RoleToken.getUnsignedToken(signedToken)
            );
            return null;
        }

        /* if the token's domain is user then we need to check to see if this is a write
         * operation (PUT/POST/DELETE) and in that case we must validate the IP
         * address of the incoming request to make sure it matches to IP address
         * that's stored in the RoleToken */
        if (
            remoteAddr !== roleToken.getIP() &&
            this._isWriteOperation(httpMethod)
        ) {
            var tokenPrincipal = roleToken.getPrincipal();
            var idx = tokenPrincipal.lastIndexOf('.');

            if (idx <= 0 || idx === tokenPrincipal.length - 1) {
                logger.error(
                    'RoleAuthority:authenticate failed: Invalid principal specified: ' +
                        tokenPrincipal +
                        ': credential=' +
                        RoleToken.getUnsignedToken(signedToken)
                );
                return null;
            }

            if (
                tokenPrincipal.substring(0, idx).toLowerCase() ===
                this._userDomain
            ) {
                logger.error(
                    'RoleAuthority:authenticate failed: IP Mismatch - tokenip(' +
                        roleToken.getIP() +
                        ') request-addr(' +
                        remoteAddr +
                        ') credential=' +
                        RoleToken.getUnsignedToken(signedToken)
                );
                return null;
            }
        }

        var publicKey = this._keyStore.getPublicKey(
            SYS_AUTH_DOMAIN,
            ZTS_SERVICE,
            roleToken.getKeyId()
        );

        if (
            roleToken.validate(publicKey, this._allowedOffset, false) === false
        ) {
            logger.error(
                'RoleAuthority:authenticate failed: validation was not successful: credential=' +
                    RoleToken.getUnsignedToken(signedToken)
            );
            return null;
        }

        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well

        var princ = SimplePrincipal.createByRoles(
            roleToken.getDomain(),
            signedToken,
            roleToken.getRoles(),
            this
        );
        princ.setUnsignedCreds(roleToken.getUnsignedToken());
        return princ;
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

    setKeyStore(keyStore) {
        this._keyStore = keyStore;
    }
}

module.exports = RoleAuthority;
