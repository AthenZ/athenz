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

var fs = require('fs');

var PrincipalAuthority = require('../../../src/impl/PrincipalAuthority');
var PrincipalToken = require('../../../src/token/PrincipalToken');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var privateKeyK0 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var privateKeyK1 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k1.pem', 'utf8'));

var keyStore = require('../../config/KeyStore');
var principalAuthorityMock = require('../../config/PrincipalAuthorityMock');

var tokenObject = {
  version: 'S1',
  domain: 'athenz.user',
  name: 'test',
  host: 'test.athenz.com',
  keyId: '0',
  ip: '172.168.0.1',
  salt: '01234abc',
  expiryTime: 30 * 24 * 60 * 60,
  authorizedServices: 'tech.store,tech.item',
  originalRequestor: 'athenz.ci.service'
};

var signedToken = 'v=S1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature;bk=0;bn=tech.store;bs=bsignature';

var remoteAddr = '172.168.0.1';
var publicKeyDomain = 'athenz.user';
var publicKeyService = 'test';
var publicKeyId = '0';
var authorizedServices = ['tech.store', 'tech.items'];
var authorizedServiceName = 'tech.store';

describe('PrincipalAuthority impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test PrincipalAuthority', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._allowedOffset).to.be.a('number');
    expect(principalAuthority._ipCheckMode).to.be.a('string');
    expect(principalAuthority._userDomain).to.be.a('string');
  });

  it('should test initialize', function() {
    var principalAuthority = new PrincipalAuthority();

    principalAuthority.initialize();
  });

  it('should test getDomain', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority.getDomain()).to.null;
  });

  it('should test getHeader', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority.getHeader()).to.be.a('string');
  });

  it('should test authenticate', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority.authenticate(serviceToken.getSignedToken(), remoteAddr, 'PUT')).to.not.be.null;
  });

  it('should test authenticate: signedToken Null: result null', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    expect(principalAuthority.authenticate(null, remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: isValidAuthorizedServiceToken false: result null', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    var invalidSignedToken = serviceToken.getSignedToken().substring(0, serviceToken.getSignedToken().indexOf(';bs='));

    expect(principalAuthority.authenticate(invalidSignedToken, remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: validate false: result null', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK1);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority.authenticate(serviceToken.getSignedToken(), remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: validation of authorized service failure: result null', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK1);

    expect(principalAuthority.authenticate(serviceToken.getSignedToken(), remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: IP Mismatch: result error', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);
    principalAuthority._ipCheckMode = 'OPS_ALL';

    var tokenObj = Object.assign({}, tokenObject);
    tokenObj.domain = 'user';

    var serviceToken = new PrincipalToken(tokenObj);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority.authenticate(serviceToken.getSignedToken(), '172.168.0.2', 'PUT')).to.be.null;
  });

  it('should test _remoteIpCheck', function() {
    var principalAuthority = new PrincipalAuthority();

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck(remoteAddr, true, serviceToken, serviceToken.getAuthorizedServiceName())).to.be.true;
  });

  it('should test _remoteIpCheck: authorizedServiceName Null and other remoteAddr: result false', function() {
    var principalAuthority = new PrincipalAuthority();

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck('172.168.0.2', true, serviceToken, null)).to.be.false;
  });

  it('should test _remoteIpCheck: other remoteAddr', function() {
    var principalAuthority = new PrincipalAuthority();

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck('172.168.0.2', true, serviceToken, serviceToken.getAuthorizedServiceName())).to.be.true;
  });

  it('should test _remoteIpCheck: writeOp false', function() {
    var principalAuthority = new PrincipalAuthority();

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck(remoteAddr, false, serviceToken, null)).to.be.true;
  });

  it('should test _remoteIpCheck ipCheckMode OPS_ALL', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority._ipCheckMode = 'OPS_ALL';

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck(remoteAddr, true, serviceToken, null)).to.be.true;
  });

  it('should test _remoteIpCheck ipCheckMode OPS_ALL: invalid remoteAddr: result false', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority._ipCheckMode = 'OPS_ALL';

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck('172.168.0.2', true, serviceToken, null)).to.be.false;
  });

  it('should test _remoteIpCheck ipCheckMode OPS_NONE', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority._ipCheckMode = 'OPS_NONE';

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck(null, null, null, null)).to.be.true;
  });

  it('should test _remoteIpCheck ipCheckMode others: result false', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority._ipCheckMode = 'OPS_READ';

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._remoteIpCheck(remoteAddr, true, serviceToken, serviceToken.getAuthorizedServiceName())).to.be.false;
  });

  it('should test _getPublicKey: keyService Null', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(principalAuthorityMock);

    expect(principalAuthority._getPublicKey(publicKeyDomain, publicKeyService, null, publicKeyId, false)).to.equal(publicKeyDomain + '.' + publicKeyService + '.' + publicKeyId);
  });

  it('should test _getPublicKey: userToken true', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(principalAuthorityMock);

    expect(principalAuthority._getPublicKey(publicKeyDomain, publicKeyService, null, publicKeyId, true)).to.equal('sys.auth.zms.' + publicKeyId);
  });

  it('should test _getPublicKey: zms', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(principalAuthorityMock);

    expect(principalAuthority._getPublicKey(publicKeyDomain, publicKeyService, 'zms', publicKeyId, false)).to.equal('sys.auth.zms.' + publicKeyId);
  });

  it('should test _getPublicKey: zts', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(principalAuthorityMock);

    expect(principalAuthority._getPublicKey(publicKeyDomain, publicKeyService, 'zts', publicKeyId, false)).to.equal('sys.auth.zts.' + publicKeyId);
  });

  it('should test _isWriteOperation: httpMethod Null: result false', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._isWriteOperation(null)).to.be.false;
  });

  it('should test _isWriteOperation: httpMethod PUT POST DELETE', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._isWriteOperation('PUT')).to.be.true;
    expect(principalAuthority._isWriteOperation('POST')).to.be.true;
    expect(principalAuthority._isWriteOperation('DELETE')).to.be.true;
  });

  it('should test _isWriteOperation: invalid httpMethod: result false', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._isWriteOperation('GET')).to.be.false;
  });

  it('should test _getAuthorizedServiceName', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._getAuthorizedServiceName(authorizedServices, authorizedServiceName)).to.equal(authorizedServiceName);
  });

  it('should test _getAuthorizedServiceName: authorizedServiceName Null and authorizedServices have only', function() {
    var principalAuthority = new PrincipalAuthority();
    var authorizeService = ['tech.store'];

    expect(principalAuthority._getAuthorizedServiceName(authorizeService, null)).to.equal(authorizeService[0]);
  });

  it('should test _getAuthorizedServiceName: authorizedServiceName Null: result null', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._getAuthorizedServiceName(authorizedServices, null)).to.be.null;
  });

  it('should test _getAuthorizedServiceName: authorizedServices doesn\'t contain authorizedServiceName: result null', function() {
    var principalAuthority = new PrincipalAuthority();

    expect(principalAuthority._getAuthorizedServiceName(authorizedServices, 'tech.storage')).to.be.null;
  });

  it('should test _validateAuthorizeService', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var serviceToken = new PrincipalToken(tokenObject);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

    expect(principalAuthority._validateAuthorizeService(serviceToken)).to.equal(serviceToken.getAuthorizedServiceName());
  });

  it('should test _validateAuthorizeService: authorizedServiceName null and authorizedServices null: result null', function() {
    var principalAuthority = new PrincipalAuthority();

    var invalidSignedToken = signedToken.substring(0, signedToken.indexOf(';b=')) + ';s=signature';
    var invalidServiceToken = new PrincipalToken(invalidSignedToken);

    expect(principalAuthority._validateAuthorizeService(invalidServiceToken)).to.be.null;
  });

  it('should test _validateAuthorizeService: authorizedServiceName null and authorizedService Only', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    var tokenObj = Object.assign({}, tokenObject);
    tokenObj.authorizedServices = 'tech.store';
    var serviceToken = new PrincipalToken(tokenObj);
    serviceToken.sign(privateKeyK0);

    serviceToken.signForAuthorizedService('tech.store', '0', privateKeyK0);

     expect(principalAuthority._validateAuthorizeService(serviceToken)).to.equal('tech.store');
  });

  it('should test _validateAuthorizeService: invalid authorizedServiceName: result null', function() {
    var principalAuthority = new PrincipalAuthority();
    var invalidSignedToken = 'v=S1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech,tech.item;s=signature;bk=0;bn=tech;bs=bsignature';
    var invalidServiceToken = new PrincipalToken(invalidSignedToken);

    expect(principalAuthority._validateAuthorizeService(invalidServiceToken)).to.be.null;

    invalidSignedToken = 'v=S1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store.,tech.item;s=signature;bk=0;bn=tech.store.;bs=bsignature';
    invalidServiceToken = new PrincipalToken(invalidSignedToken);

    expect(principalAuthority._validateAuthorizeService(invalidServiceToken)).to.be.null;
  });

  it('should test _validateAuthorizeService: token validation for authorized service failed', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);
    var invalidServiceToken = new PrincipalToken(signedToken);

    expect(principalAuthority._validateAuthorizeService(invalidServiceToken)).to.be.null;
  });

  it('should test setKeyStore', function() {
    var principalAuthority = new PrincipalAuthority();
    principalAuthority.setKeyStore(keyStore);

    expect(principalAuthority._keyStore).to.not.be.null;
  });
});
