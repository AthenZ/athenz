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

const logger = require('./logger');

// configurable fields
let config = require('./config/config.js')();
let cacheDisabled = false;
let tokenMinExpiryTime = 900;

class ZTSClient {
    constructor(params) {
        this._ztsUrl = null;
        this._domain = null;
        this._service = null;
        this._ztsClient = null;
        this._ztsClientFactory = null;
        this._siaProvider = null;

        this._enablePrefetch = true;
        this.principal = null;
        this._cache = require('memory-cache');

        this._initClient(params);
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.ztsClient);
    }

    static _initConfigValues() {
        /* The minimum token expiry time by default is 15 minutes (900). By default the
         * server gives out role tokens for 2 hours and with this setting we'll be able
         * to cache tokens for 1hr45mins before requesting a new one from ZTS */
        if (config.tokenMinExpiryTime >= 0) {
            tokenMinExpiryTime = config.tokenMinExpiryTime;
        } else {
            tokenMinExpiryTime = 900;
        }

        if (config.disableCache) {
            cacheDisabled = config.disableCache;
        } else {
            cacheDisabled = false;
        }

        return true;
    }

    /*eslint complexity: ["error", 11]*/
    _initClient(params) {
        if (params.domainName || params.serviceName || params.siaProvider) {
            if (
                !params.domainName ||
                !params.serviceName ||
                !params.siaProvider
            ) {
                throw new Error(
                    'domainName & serviceName & siaProvider must be specified.'
                );
            }
            this._domain = params.domainName;
            this._service = params.serviceName;
            this._siaProvider = params.siaProvider;
        } else if (params.identity) {
            if (!params.identity.getAuthority()) {
                throw new Error('Principal Authority cannot be null');
            }
            this.principal = params.identity;
            this._enablePrefetch = false; // can't use this domain and service for prefetch
        } else {
            this._enablePrefetch = false; // can't use this domain and service for prefetch
        }

        if (params.zts) {
            this._ztsUrl = params.zts;
        } else {
            this._ztsUrl = config.zts;
        }

        this._ztsClientFactory = require('./libs/rdl-rest')({
            apiHost: this._ztsUrl,
            rdl: require('./config/zts.json'),
            requestOpts: {
                strictSSL: config.strictSSL,
            },
        });

        if (this.principal) {
            this._domain = this.principal.getDomain();
            this._service = this.principal.getName();
            this._ztsClient = this._ztsClientFactory(null, {
                [this.principal.getAuthority().getHeader()]:
                    this.principal.getCredentials(),
            });
        }
    }

    _addPrincipalCredentials(identity, resetServiceDetails) {
        if (identity && identity.getAuthority()) {
            this._ztsClient = this._ztsClientFactory(null, {
                [identity.getAuthority().getHeader()]:
                    identity.getCredentials(),
            });
        }

        // if the client is adding new principal identity then we have to
        // clear out the sia provider object reference so that we don't try
        // to get a service token since we already have one given to us
        if (resetServiceDetails) {
            this._siaProvider = null;
        }

        this.principal = identity;
        return this;
    }

    _sameCredentialsAsBefore(svcPrincipal) {
        // if we don't have a principal or no credentials
        // then the principal has changed
        if (!this.principal) {
            return false;
        }

        const creds = this.principal.getCredentials();
        if (!creds) {
            return false;
        }

        return creds === svcPrincipal.getCredentials();
    }

    _updateServicePrincipal() {
        /* if we have a service principal then we need to keep updating
         * our PrincipalToken otherwise it might expire. */
        if (!this._siaProvider) {
            return false;
        }

        const svcPrincipal = this._siaProvider.getIdentity(
            this._domain,
            this._service
        );

        // if we get no principal from our sia provider, then we
        // should log and throw an IllegalArgumentException otherwise the
        // client doesn't know that something bad has happened - in this
        // case illegal domain/service was passed to the constructor
        // and the ZTS Server just rejects the request with 401
        if (!svcPrincipal) {
            const msg =
                'UpdateServicePrincipal: Unable to get PrincipalToken ' +
                'from SIA Provider for ' +
                this._domain +
                '.' +
                this._service;
            logger.error(msg);
            throw new Error(msg);
        }

        // if the principal has the same credentials as before
        // then we don't need to update anything
        if (this._sameCredentialsAsBefore(svcPrincipal)) {
            return false;
        }

        this._addPrincipalCredentials(svcPrincipal, false);
        return true;
    }

    getRoleToken(params, cb) {
        const pars = Object.assign(
            {
                domainName: null,
                roleName: null,
                minExpiryTime: null,
                maxExpiryTime: null,
                ignoreCache: false,
                proxyForPrincipal: null,
            },
            params
        );
        const that = this;

        if (!pars.domainName) {
            return cb(
                new Error('GetRoleToken: domainName must not be null.'),
                null
            );
        }

        let roleToken = null;

        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache
        let cacheKey = null;
        if (!cacheDisabled) {
            cacheKey = this._getRoleTokenCacheKeySetTenant(
                pars.domainName,
                pars.roleName,
                pars.proxyForPrincipal
            );
            if (cacheKey && !params.ignoreCache) {
                roleToken = this._lookupRoleTokenInCache(
                    cacheKey,
                    pars.minExpiryTime,
                    pars.maxExpiryTime
                );
                if (roleToken) {
                    return cb(null, roleToken);
                }
            }
        }

        // if no hit then we need to request a new token from ZTS
        this._updateServicePrincipal();
        this._ztsClient.getRoleToken(pars, function (err, res) {
            if (err) {
                return cb(err, null);
            }
            // need to add the token to our cache. If our principal was
            // updated then we need to retrieve a new cache key

            if (!cacheDisabled) {
                if (cacheKey) {
                    that._cache.put(cacheKey, res, config.tokenRefresh * 1000);
                }
            }
            return cb(null, res);
        });
    }

    _getRoleTokenCacheKeySetTenant(domainName, roleName, proxyForPrincipal) {
        return this._getRoleTokenCacheKey(
            this._domain,
            this._service,
            domainName,
            roleName,
            proxyForPrincipal
        );
    }

    _getRoleTokenCacheKey(
        tenantDomain,
        tenantService,
        domainName,
        roleName,
        proxyForPrincipal
    ) {
        if (!tenantDomain) {
            return null;
        }
        let cacheKey = 'p=' + tenantDomain;
        if (tenantService) {
            cacheKey += '.' + tenantService;
        }
        cacheKey += ';d=' + domainName;

        if (roleName) {
            cacheKey += ';r=' + roleName;
        }
        if (proxyForPrincipal) {
            cacheKey += ';u=' + proxyForPrincipal;
        }

        return cacheKey;
    }

    _isExpiredToken(
        expiryTime,
        minExpiryTime,
        maxExpiryTime,
        tokenMinExpiryTime
    ) {
        // we'll first make sure if we're given both min and max expiry
        // times then both conditions are satisfied
        if (minExpiryTime && expiryTime < minExpiryTime) {
            return true;
        }

        if (maxExpiryTime && expiryTime > maxExpiryTime) {
            return true;
        }

        // if both limits were null then we need to make sure
        // that our token is valid for based on our min configured value
        if (
            !minExpiryTime &&
            !maxExpiryTime &&
            expiryTime < tokenMinExpiryTime
        ) {
            return true;
        }

        return false;
    }

    _lookupRoleTokenInCache(cacheKey, minExpiryTime, maxExpiryTime) {
        const roleToken = this._cache.get(cacheKey);
        if (!roleToken) {
            logger.info(
                'LookupRoleTokenInCache: cache-lookup key: ' +
                    cacheKey +
                    ' result: not found'
            );
            return null;
        }

        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        const expiryTime = roleToken.expiryTime - Math.floor(Date.now() / 1000);
        if (
            this._isExpiredToken(
                expiryTime,
                minExpiryTime,
                maxExpiryTime,
                tokenMinExpiryTime
            )
        ) {
            logger.info(
                'LookupRoleTokenInCache: role-cache-lookup key: ' +
                    cacheKey +
                    ' token-expiry: ' +
                    expiryTime +
                    ' req-min-expiry: ' +
                    this.minExpiryTime +
                    ' req-max-expiry: ' +
                    this.maxExpiryTime +
                    ' client-min-expiry: ' +
                    tokenMinExpiryTime +
                    ' result: expired'
            );
            this._cache.del(cacheKey);
            return null;
        }
        return roleToken;
    }
}

ZTSClient._initConfigValues();
module.exports = ZTSClient;
