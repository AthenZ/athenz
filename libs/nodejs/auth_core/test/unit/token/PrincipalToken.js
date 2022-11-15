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

var PrincipalToken = require('../../../src/token/PrincipalToken');

var fs = require('fs');
var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var signedToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature;bk=0;bn=tech.store;bs=bsignature';
var tokenObject = {
  version: 'U1',
  domain: 'athenz.user',
  name: 'test',
  host: 'test.athenz.com',
  keyId: '0',
  ip: '172.168.0.1',
  salt: '01234abc',
  authorizedServices: 'tech.store,tech.item',
  keyService: 'zms',
  originalRequestor: 'athenz.ci.service'
};

var privateKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var publicKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k0.pem', 'utf8'));
var publicKey01 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k1.pem', 'utf8'));

describe('PrincipalToken impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test PrincipalToken: null: result error', function() {
    try {
      var principalToken = new PrincipalToken(null);
    } catch (e) {
      expect(e.message).to.contain('Cannot read properties');
      return;
    }
    expect(1).to.be.false;
  });

  it('should test PrincipalToken: using signedToken', function() {
    var principalToken = new PrincipalToken(signedToken);

    expect(principalToken.getVersion()).to.equal('U1');
    expect(principalToken.getDomain()).to.equal('athenz.user');
    expect(principalToken.getName()).to.equal('test');
    expect(principalToken.getHost()).to.equal('test.athenz.com');
    expect(principalToken.getIP()).to.equal('172.168.0.1');
    expect(principalToken.getKeyId()).to.equal('0');

    expect(principalToken.getKeyService()).to.equal('zms');
    expect(principalToken.getOriginalRequestor()).to.equal('athenz.ci.service');

    expect(principalToken.getSalt()).to.equal('01234abc');
    expect(principalToken.getTimestamp()).to.equal(10000);
    expect(principalToken.getExpiryTime()).to.equal(30);
    expect(principalToken.getSignature()).to.equal('signature');

    expect(principalToken.getAuthorizedServices()).to.contain('tech.store');
    expect(principalToken.getAuthorizedServices()).to.contain('tech.item');
    expect(principalToken.getAuthorizedServiceName()).to.equal('tech.store');
    expect(principalToken.getAuthorizedServiceKeyId()).to.equal('0');
    expect(principalToken.getAuthorizedServiceSignature()).to.equal('bsignature');

    expect(principalToken.getUnsignedToken()).to.equal('v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item');
    expect(principalToken.getSignedToken()).to.equal('v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature;bk=0;bn=tech.store;bs=bsignature');
  });

  it('should test PrincipalToken: using signedToken: signedToken Null: result error', function() {
    var principalToken = new PrincipalToken(signedToken);

    try {
      principalToken.parseSignedToken(null);
    } catch (e) {
      expect(e.message).to.equal('Input String signedToken must not be empty');
      return;
    }
    expect(1).to.be.false;
  });

  it('should test PrincipalToken: using signedToken: domain Null: result error', function() {
    try {
      var principalToken = new PrincipalToken('v=U1;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;s=signature;');
    } catch (e) {
      expect(e.message).to.equal('SignedToken does not contain required domain component');
      return;
    }
    expect(1).to.be.false;
  });

  it('should test PrincipalToken: using signedToken: name Null: result error', function() {
    try {
      var principalToken = new PrincipalToken('v=U1;d=athenz;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;s=signature;');
    } catch (e) {
      expect(e.message).to.equal('SignedToken does not contain required name component');
      return;
    }
    expect(1).to.be.false;
  });

  it('should test PrincipalToken: using tokenObject', function() {
    var principalToken = new PrincipalToken(tokenObject);

    expect(principalToken.getVersion()).to.equal('U1');
    expect(principalToken.getDomain()).to.equal('athenz.user');
    expect(principalToken.getName()).to.equal('test');
    expect(principalToken.getHost()).to.equal('test.athenz.com');
    expect(principalToken.getIP()).to.equal('172.168.0.1');
    expect(principalToken.getKeyId()).to.equal('0');

    expect(principalToken.getKeyService()).to.equal('zms');
    expect(principalToken.getOriginalRequestor()).to.equal('athenz.ci.service');

    expect(principalToken.getSalt()).to.equal('01234abc');
    expect(principalToken.getTimestamp()).to.be.a('number');
    expect(principalToken.getExpiryTime()).to.be.a('number');


    expect(principalToken.getAuthorizedServices()).to.contain('tech.store');
    expect(principalToken.getAuthorizedServices()).to.contain('tech.item');

    expect(principalToken.getUnsignedToken()).to.be.a('String');
  });

  it('should test PrincipalToken: using tokenObject: version Null: result error', function() {
    var tokenObj = Object.assign({}, tokenObject);
    delete tokenObj.version;

    try {
      var principalToken = new PrincipalToken(tokenObj);
    } catch (e) {
      expect(e.message).to.equal('version, domain and name parameters must not be null.');
      return;
    }
    expect(1).to.be.false;

  });

  it('should test PrincipalToken: using tokenObject: domain Null: result error', function() {
    var tokenObj = Object.assign({}, tokenObject);
    delete tokenObj.domain;

    try {
      var principalToken = new PrincipalToken(tokenObj);
    } catch (e) {
      expect(e.message).to.equal('version, domain and name parameters must not be null.');
      return;
    }
    expect(1).to.be.false;

  });

  it('should test PrincipalToken: using tokenObject: name Null: result error', function() {
    var tokenObj = Object.assign({}, tokenObject);
    delete tokenObj.name;

    try {
      var principalToken = new PrincipalToken(tokenObj);
    } catch (e) {
      expect(e.message).to.equal('version, domain and name parameters must not be null.');
      return;
    }
    expect(1).to.be.false;

  });

  it('should test signForAuthorizedService', function() {
    var sigToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature';
    var principalToken = new PrincipalToken(sigToken);

    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.getAuthorizedServiceName()).to.equal('tech.item');
    expect(principalToken.getAuthorizedServiceKeyId()).to.equal('0');
    expect(principalToken.getAuthorizedServiceSignature()).to.be.a('String');
    expect(principalToken.getSignedToken()).to.be.a('String');
  });

  it('should test signForAuthorizedService: invalid authorizedServiceName: result error', function() {
    var sigToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature';
    var principalToken = new PrincipalToken(sigToken);

    try {
      principalToken.signForAuthorizedService('tech.sample', '0', privateKey);
    } catch (e) {
      expect(e.message).to.equal('Authorized Service is not valid for this token');
      return;
    }

    expect(1).to.be.false;
  });

  it('should test signForAuthorizedService: authorizedServiceName Null: result error', function() {
    var sigToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature';
    var principalToken = new PrincipalToken(sigToken);

    try {
      principalToken.signForAuthorizedService(null, '0', privateKey);
    } catch (e) {
      expect(e.message).to.equal('Authorized Service is not valid for this token');
      return;
    }

    expect(1).to.be.false;
  });

  it('should test validateForAuthorizedService', function() {
    var sigToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature';
    var principalToken = new PrincipalToken(sigToken);

    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.validateForAuthorizedService(publicKey)).to.be.true;
  });

  it('should test validateForAuthorizedService: authorizedServiceSignature Null: result false', function() {
    var principalToken = new PrincipalToken(tokenObject);

    expect(principalToken.validateForAuthorizedService(publicKey)).to.be.false;
  });

  it('should test validateForAuthorizedService: signedTokrn no Authorized signature: result false', function() {
    var sigToken = 'v=U1;d=athenz.user;n=test;h=test.athenz.com;a=01234abc;t=10000;e=30;k=0;z=zms;o=athenz.ci.service;i=172.168.0.1;b=tech.store,tech.item;s=signature';
    var principalToken = new PrincipalToken(sigToken);

    principalToken.signForAuthorizedService('tech.item', '0', privateKey);
    principalToken._signedToken = principalToken._signedToken.substring(0, principalToken._signedToken.indexOf(';bs='));

    expect(principalToken.validateForAuthorizedService(publicKey)).to.be.false;
  });

  it('should test validateForAuthorizedService: publicKey Null: result false', function() {
    var principalToken = new PrincipalToken(tokenObject);
    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.validateForAuthorizedService(null)).to.be.false;
  });

  it('should test validateForAuthorizedService: other publicKey: result false', function() {
    var principalToken = new PrincipalToken(tokenObject);
    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.validateForAuthorizedService(publicKey01)).to.be.false;
  });

  it('should test validateForAuthorizedService: invalid publicKey: result false', function() {
    var principalToken = new PrincipalToken(tokenObject);
    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.validateForAuthorizedService('testPublicKey')).to.be.false;
  });

  it('should test isValidAuthorizedServiceToken', function() {
    var principalToken = new PrincipalToken(tokenObject);

    principalToken.signForAuthorizedService('tech.item', '0', privateKey);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.true;
  });

  it('should test isValidAuthorizedServiceToken: no authorizedServices and no authorizedServiceSignature', function() {
    var tokenObj = Object.assign({}, tokenObject);
    delete tokenObj.authorizedServices;
    var principalToken = new PrincipalToken(tokenObj);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.true;
  });

  it('should test isValidAuthorizedServiceToken: authorizedServices contains only entry', function() {
    var tokenStr = 'v=S1;d=athenz.user;n=test;a=01234abc;t=10000;e=30;k=0;b=tech.store;s=signature;bk=0;bs=bsignature';
    var principalToken = new PrincipalToken(tokenStr);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.true;
  });

  it('should test isValidAuthorizedServiceToken: authorizedServices Null and existed authorizedServiceSignature: result false', function() {
    var tokenStr = 'v=S1;d=athenz.user;n=test;a=01234abc;t=10000;e=30;k=0;s=signature;bk=0;bs=bsignature';
    var principalToken = new PrincipalToken(tokenStr);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.false;
  });

  it('should test isValidAuthorizedServiceToken: authorizedServiceSignature Null: result false', function() {
    var tokenStr = 'v=S1;d=athenz.user;n=test;a=01234abc;t=10000;e=30;k=0;b=tech.store,tech.item;s=signature;bk=0;';
    var principalToken = new PrincipalToken(tokenStr);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.false;
  });

  it('should test isValidAuthorizedServiceToken: authorizedServices doesn\'t include authorizedServiceName: result false', function() {
    var tokenStr = 'v=S1;d=athenz.user;n=test;a=01234abc;t=10000;e=30;k=0;b=tech.store,tech.item;s=signature;bk=0;bn=tech.sample;bs=bsignature';
    var principalToken = new PrincipalToken(tokenStr);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.false;
  });

  it('should test isValidAuthorizedServiceToken: No service name and Authorized service list contains multiple entries: result false', function() {
    var tokenStr = 'v=S1;d=athenz.user;n=test;a=01234abc;t=10000;e=30;k=0;b=tech.store,tech.item;s=signature;bk=0;bs=bsignature';
    var principalToken = new PrincipalToken(tokenStr);

    expect(principalToken.isValidAuthorizedServiceToken()).to.be.false;
  });
});
