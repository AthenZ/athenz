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

var PrincipalAuthority = require('./PrincipalAuthority');
var PrincipalToken = require('../token/PrincipalToken');
var SimplePrincipal = require('./SimplePrincipal');

var os = require('os');

class SimpleServiceIdentityProvider {
    /**
     * A simple implementation of the ServiceIdentityProvider interface.
     * The caller specifies the domain and service name along with the
     * private key for the given service
     * @param domainName Name of the domain
     * @param serviceName Name of the service
     * @param privateKey the private key for the service
     * @param keyId the registered key id in ZMS for this private key
     */
    constructor(domainName, serviceName, privateKey, keyId) {
        this._Authority = new PrincipalAuthority();

        this._domain = domainName.toString().toLowerCase();
        this._service = serviceName.toString().toLowerCase();
        this._key = privateKey;
        this._tokenTimeout = 3600;
        this._keyId = keyId.toString().toLowerCase();
        this.setHost(this._getServerHostName());
    }

    static setConfig(c) {
        PrincipalAuthority.setConfig(c);
        PrincipalToken.setConfig(c);
        SimplePrincipal.setConfig(c);
    }

    getIdentity(domainName, serviceName) {
        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        domainName = domainName.toString().toLowerCase();
        serviceName = serviceName.toString().toLowerCase();

        // make sure we're handling correct domain and service
        if (domainName !== this._domain || serviceName !== this._service) {
            return null;
        }

        var tokenObj = {
            version: 'S1',
            domain: domainName,
            name: serviceName,
            expirationWindow: this._tokenTimeout,
            host: this._host,
            keyId: this._keyId,
        };

        var token = new PrincipalToken(tokenObj);
        token.sign(this._key);

        var principal = SimplePrincipal.createByUserIdentity(
            domainName,
            serviceName,
            token.getSignedToken(),
            Math.floor(Date.now() / 1000),
            this._Authority
        );
        principal.setUnsignedCreds(token.getUnsignedToken());
        return principal;
    }

    _getServerHostName() {
        var urlhost = null;

        try {
            urlhost = os.hostname();
        } catch (e) {
            urlhost = 'localhost';
        }

        return urlhost;
    }

    getHost() {
        return this._host;
    }

    setHost(host) {
        this._host = host;
    }

    setTokenTimeout(tokenTimeout) {
        this._tokenTimeout = tokenTimeout;
    }
}

module.exports = SimpleServiceIdentityProvider;
