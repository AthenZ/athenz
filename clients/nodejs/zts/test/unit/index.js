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

var ztsClient = require('../../index');

var sinon = require('sinon');
var expect = require('chai').expect;
var cache = require('memory-cache');

var siaProviderMock = require('../config/SiaProviderMock');
var identityMock = require('../config/IdentityMock');
var roleTokenMock = require('../config/RoleTokenMock');
var rdlMock = require('../config/RdlMock');

var sandbox;

var params = {
    zts: 'zts.athenz.com',
    domainName: null,
    serviceName: null,
    siaProvider: null,
    identity: null,
};

var domainName = 'athenz.user';
var serviceName = 'test';

var siaMock = new siaProviderMock(domainName, serviceName);
var ideMock = new identityMock(domainName, serviceName);

var siaParams = {
    zts: 'zts.athenz.com',
    domainName: domainName,
    serviceName: serviceName,
    siaProvider: siaMock,
    identity: null,
};

var paramsR = {
    domainName: 'athenz.com',
    roleName: 'front',
    minExpiryTime: 900,
    maxExpiryTime: 1400,
    ignoreCache: false,
    proxyForPrincipal: 'proxy',
};

var cacheKey = 'cacheKeyRoleToken';

describe('zts_client impl', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it('should test zts_client', function () {
        var zts = new ztsClient(params);

        expect(zts).to.not.be.null;

        expect(zts._ztsUrl).to.equal(params.zts);
        expect(zts._domain).to.be.null;
        expect(zts._service).to.be.null;
        expect(zts._siaProvider).to.be.null;
        expect(zts.principal).to.be.null;

        expect(zts.cacheDisabled).to.not.be.null;
        expect(zts.tokenMinExpiryTime).to.not.be.null;
        expect(zts.prefetchInterval).to.not.be.null;
        expect(zts.prefetchAutoEnable).to.not.be.null;

        expect(zts._enablePrefetch).to.be.false;
    });

    it('should test _initConfigValues', function () {
        try {
            ztsClient._initConfigValues();
        } catch (e) {
            expect(1).to.be.false;
        }
    });

    it('should test _initClient: domainName & serviceName & siaProvider', function () {
        var zts = new ztsClient(siaParams);

        expect(zts._ztsUrl).to.equal(siaParams.zts);
        expect(zts._domain).to.equal(siaParams.domainName);
        expect(zts._service).to.equal(siaParams.serviceName);
        expect(zts._siaProvider).to.equal(siaParams.siaProvider);
        expect(zts.principal).to.be.null;
    });

    it('should test _initClient: domainName or serviceName or siaProvidr be null: result error', function () {
        var pars = Object.assign({}, params);

        pars.siaProvider = siaMock;

        try {
            new ztsClient(pars);
        } catch (e) {
            expect(e.message).to.contain(
                'domainName & serviceName & siaProvider must be specified.'
            );
            return;
        }
        expect(1).to.be.false;
    });

    it('should test _initClient: identity', function () {
        var pars = Object.assign({}, params);
        pars.ztsUrl = null;

        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        expect(zts._ztsUrl).to.not.be.null;
        expect(zts._domain).to.equal(pars.identity.getDomain());
        expect(zts._service).to.equal(pars.identity.getName());
        expect(zts._siaProvider).to.be.null;
        expect(zts.principal).to.equal(pars.identity);
        expect(zts._ztsClient).to.not.be.null;
    });

    it('should test _initClient: identity.getAuthority() null: result error', function () {
        var pars = Object.assign({}, params);

        var ideMockInv = new identityMock(null, null);
        pars.identity = ideMockInv;

        try {
            new ztsClient(pars);
        } catch (e) {
            expect(e.message).to.contain('Principal Authority cannot be null');
            return;
        }
        expect(1).to.be.false;
    });

    it('should test _addPrincipalCredentials: resetServiceDetails true', function () {
        var zts = new ztsClient(params);

        zts._addPrincipalCredentials(ideMock, true);

        expect(zts._ztsClient).to.not.be.null;
        expect(zts._siaProvider).to.be.null;
        expect(zts.principal).to.equal(ideMock);
    });

    it('should test _addPrincipalCredentials: resetServiceDetails false', function () {
        var zts = new ztsClient(siaParams);

        zts._addPrincipalCredentials(ideMock, false);

        expect(zts._ztsClient).to.not.be.null;
        expect(zts._siaProvider).to.equal(siaMock);
        expect(zts.principal).to.equal(ideMock);
    });

    it('should test _addPrincipalCredentials: identity null', function () {
        var zts = new ztsClient(params);

        zts._addPrincipalCredentials(null, true);

        expect(zts._ztsClient).to.be.null;
        expect(zts.principal).to.be.null;
    });

    it('should test _addPrincipalCredentials: identity.getAuthority() null', function () {
        var zts = new ztsClient(params);

        var ideMockInv = new identityMock(null, null);
        zts._addPrincipalCredentials(ideMockInv, true);

        expect(zts._ztsClient).to.be.null;
        expect(zts.principal).to.equal(ideMockInv);
    });

    it('should test _sameCredentialsAsBefore', function () {
        var pars = Object.assign({}, params);
        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        expect(zts._sameCredentialsAsBefore(ideMock)).to.be.true;
    });

    it('should test _sameCredentialsAsBefore: principal null: result false', function () {
        var zts = new ztsClient(params);

        expect(zts._sameCredentialsAsBefore(ideMock)).to.be.false;
    });

    it('should test _sameCredentialsAsBefore: principal.getCredentials() null: result false', function () {
        var pars = Object.assign({}, params);

        var ideMockInv = new identityMock(domainName, null);

        pars.identity = ideMockInv;
        var zts = new ztsClient(pars);

        expect(zts._sameCredentialsAsBefore(ideMock)).to.be.false;
    });

    it('should test _sameCredentialsAsBefore: no match creds: result false', function () {
        var pars = Object.assign({}, params);
        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        var ideMockAn = new identityMock('athenz.user', 'test2');

        expect(zts._sameCredentialsAsBefore(ideMockAn)).to.be.false;
    });

    it('should test _updateServicePrincipal', function () {
        var zts = new ztsClient(siaParams);

        expect(zts._updateServicePrincipal()).to.be.true;
    });

    it('should test _updateServicePrincipal: siaProvider null: result false', function () {
        var zts = new ztsClient(params);

        expect(zts._updateServicePrincipal()).to.be.false;
    });

    it('should test _updateServicePrincipal: siaProvider.getIdentity null: result error', function () {
        var pars = Object.assign({}, siaParams);

        var siaMockInv = new siaProviderMock(domainName, null);

        pars.siaProvider = siaMockInv;
        var zts = new ztsClient(pars);

        try {
            zts._updateServicePrincipal();
        } catch (e) {
            expect(e.message).to.contain(
                'UpdateServicePrincipal: Unable to get PrincipalToken'
            );
            return;
        }
        expect(1).to.be.false;
    });

    it('should test _updateServicePrincipal: identity null: result false', function () {
        var zts = new ztsClient(siaParams);

        zts._addPrincipalCredentials(ideMock, false);

        expect(zts._updateServicePrincipal()).to.be.false;
    });

    it('should test getRoleToken: get cache', function () {
        var zts = new ztsClient(siaParams);

        var roleToken = new roleTokenMock(20000);
        var ck =
            'p=' +
            domainName +
            '.' +
            serviceName +
            ';d=' +
            paramsR.domainName +
            ';r=' +
            paramsR.roleName +
            ';u=' +
            paramsR.proxyForPrincipal;
        cache.del(ck);
        cache.put(ck, roleToken);

        var rT = null;
        zts.getRoleToken(paramsR, function (err, res) {
            if (err) {
                throw err;
            }
            rT = res;
        });
        expect(rT).to.equal(roleToken);
    });

    it('should test getRoleToken: domainName Null', function () {
        var zts = new ztsClient(siaParams);

        var parsR = Object.assign({}, paramsR);
        parsR.domainName = null;

        var rT = null;
        try {
            zts.getRoleToken(parsR, function (err, res) {
                if (err) {
                    throw err;
                }
                rT = res;
            });
        } catch (e) {
            expect(e.message).to.contain(
                'GetRoleToken: domainName must not be null.'
            );
            return;
        }
        expect(1).to.be.false;
    });

    it('should test getRoleToken: no cache & get RoleToken', function () {
        var pars = Object.assign({}, params);
        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        var roleToken = new roleTokenMock(20000);
        zts._ztsClient = new rdlMock(roleToken, true);

        var ck =
            'p=' +
            domainName +
            '.' +
            serviceName +
            ';d=' +
            paramsR.domainName +
            ';r=' +
            paramsR.roleName +
            ';u=' +
            paramsR.proxyForPrincipal;
        cache.del(ck);

        var rT = null;
        zts.getRoleToken(paramsR, function (err, res) {
            if (err) {
                throw err;
            }
            rT = res;
        });
        expect(rT).to.equal(roleToken);
        expect(cache.get(ck)).to.equal(roleToken);
    });

    it('should test getRoleToken: no cache & cannot get RoleToken: result error', function () {
        var pars = Object.assign({}, params);
        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        var roleToken = new roleTokenMock(20000);
        zts._ztsClient = new rdlMock(roleToken, false);

        var ck =
            'p=' +
            domainName +
            '.' +
            serviceName +
            ';d=' +
            paramsR.domainName +
            ';r=' +
            paramsR.roleName +
            ';u=' +
            paramsR.proxyForPrincipal;
        cache.del(ck);

        var rT = null;
        try {
            zts.getRoleToken(paramsR, function (err, res) {
                if (err) {
                    throw err;
                }
                rT = res;
            });
        } catch (e) {
            expect(e.message).to.contain('rdlMock: Error');
            return;
        }
        expect(1).to.be.false;
    });

    it('should test getRoleToken: cannot get cacheKey', function () {
        var pars = Object.assign({}, params);
        var zts = new ztsClient(pars);

        var roleToken = new roleTokenMock(20000);
        zts._ztsClient = new rdlMock(roleToken, true);

        var rT = null;
        zts.getRoleToken(paramsR, function (err, res) {
            if (err) {
                throw err;
            }
            rT = res;
        });
        expect(rT).to.equal(roleToken);
    });

    it('should test _getRoleTokenCacheKeySetTenant', function () {
        var pars = Object.assign({}, params);
        pars.identity = ideMock;
        var zts = new ztsClient(pars);

        expect(
            zts._getRoleTokenCacheKeySetTenant(
                paramsR.domainName,
                paramsR.roleName,
                paramsR.proxyForPrincipal
            )
        ).to.equal(
            'p=' +
                domainName +
                '.' +
                serviceName +
                ';d=' +
                paramsR.domainName +
                ';r=' +
                paramsR.roleName +
                ';u=' +
                paramsR.proxyForPrincipal
        );
    });

    it('should test _getRoleTokenCacheKey: tenantDomain null: result null', function () {
        var zts = new ztsClient(params);

        expect(
            zts._getRoleTokenCacheKey(
                null,
                serviceName,
                paramsR.domainName,
                paramsR.roleName,
                paramsR.proxyForPrincipal
            )
        ).to.be.null;
    });

    it('should test _getRoleTokenCacheKey: tenantService null', function () {
        var zts = new ztsClient(params);

        expect(
            zts._getRoleTokenCacheKey(
                domainName,
                null,
                paramsR.domainName,
                paramsR.roleName,
                paramsR.proxyForPrincipal
            )
        ).to.equal(
            'p=' +
                domainName +
                ';d=' +
                paramsR.domainName +
                ';r=' +
                paramsR.roleName +
                ';u=' +
                paramsR.proxyForPrincipal
        );
    });

    it('should test _getRoleTokenCacheKey: roleName null', function () {
        var zts = new ztsClient(params);

        expect(
            zts._getRoleTokenCacheKey(
                domainName,
                serviceName,
                paramsR.domainName,
                null,
                paramsR.proxyForPrincipal
            )
        ).to.equal(
            'p=' +
                domainName +
                '.' +
                serviceName +
                ';d=' +
                paramsR.domainName +
                ';u=' +
                paramsR.proxyForPrincipal
        );
    });

    it('should test _getRoleTokenCacheKey: proxyForPrincipal null', function () {
        var zts = new ztsClient(params);

        expect(
            zts._getRoleTokenCacheKey(
                domainName,
                serviceName,
                paramsR.domainName,
                paramsR.roleName,
                null
            )
        ).to.equal(
            'p=' +
                domainName +
                '.' +
                serviceName +
                ';d=' +
                paramsR.domainName +
                ';r=' +
                paramsR.roleName
        );
    });

    it('should test _isExpiredToken', function () {
        var zts = new ztsClient(params);

        expect(zts._isExpiredToken(60, 100, 150, 900)).to.be.true;
        expect(zts._isExpiredToken(180, 100, 150, 900)).to.be.true;
        expect(zts._isExpiredToken(60, null, null, 900)).to.be.true;
        expect(zts._isExpiredToken(120, 100, 150, 900)).to.be.false;
        expect(zts._isExpiredToken(910, null, null, 900)).to.be.false;
    });

    it('should test _lookupRoleTokenInCache', function () {
        var zts = new ztsClient(params);

        var roleToken = new roleTokenMock(20000);
        cache.del(cacheKey);
        cache.put(cacheKey, roleToken);

        expect(zts._lookupRoleTokenInCache(cacheKey)).to.equal(roleToken);
    });

    it('should test _lookupRoleTokenInCache: no cache: result null', function () {
        var zts = new ztsClient(params);
        cache.del(cacheKey);

        expect(zts._lookupRoleTokenInCache(cacheKey)).to.be.null;
    });

    it('should test _lookupRoleTokenInCache: exceed expiryTime: result null', function () {
        var zts = new ztsClient(params);

        var roleToken = new roleTokenMock(100);
        cache.del(cacheKey);
        cache.put(cacheKey, roleToken);

        expect(zts._lookupRoleTokenInCache(cacheKey)).to.equal(roleToken);
    });
});
