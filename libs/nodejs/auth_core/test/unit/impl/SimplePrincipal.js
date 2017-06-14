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

var SimplePrincipal = require('../../../src/impl/SimplePrincipal');
var PrincipalAuthority = require('../../../src/impl/PrincipalAuthority');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var simplePrincipalMock = require('../../config/SimplePrincipalMock');

var fakeDomain = 'user';
var fakeName = 'jdoe';
var fakeUnsignedCreds = 'v=U1;d=user;n=jdoe';
var fakeCreds = fakeUnsignedCreds + ';s=signature';
var fakeRoles = ['role1', 'role2'];
var fakeAppId = 'test.athenz.test';
var fakeAuthorizedService = 'tech.item';
var fakeIP = '172.168.0.1';
var fakeOriginalRequestor = 'athenz.ci.service';
var fakeKeyService = 'test.test';
var fakeKeyId = '0';
var fakeCert = 'cert';

var fakeAuthority = new PrincipalAuthority();

describe('SimplePrincipal impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test create', function() {
    fakeAuthority._Domain = fakeDomain;
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
    expect(simplePrincipal.getName()).to.equal(fakeName);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.be.null;
  });

  it('should test createByRoles', function() {
    var simplePrincipal = SimplePrincipal.createByRoles(fakeDomain, fakeCreds, fakeRoles, fakeAuthority);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
    expect(simplePrincipal.getRoles()).to.contain('role1');
    expect(simplePrincipal.getRoles()).to.contain('role2');
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.not.be.null;
  });

  it('should test createByRoles: invalid domain or invalid roles', function() {
    try {
      var simplePrincipal = SimplePrincipal.createByRoles('@@@@', fakeCreds, null, fakeAuthority);
      expect(simplePrincipal).to.not.be.null;
      simplePrincipal = SimplePrincipal.createByRoles('@@@@', fakeCreds, [], fakeAuthority);
      expect(simplePrincipal).to.not.be.null;
    } catch (e) {
      expect(1).to.be.false;
    }
  });

  it('should test createByIdentity', function() {
    fakeAuthority._Domain = fakeDomain;
    var simplePrincipal = SimplePrincipal.createByIdentity(fakeDomain, fakeName, fakeCreds, fakeAuthority);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
    expect(simplePrincipal.getName()).to.equal(fakeName);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.not.be.null;
  });

  it('should test createByUserIdentity', function() {
    fakeAuthority._Domain = fakeDomain;
    var simplePrincipal = SimplePrincipal.createByUserIdentity(fakeDomain, fakeName, fakeCreds, 0, fakeAuthority);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
    expect(simplePrincipal.getName()).to.equal(fakeName);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.not.be.null;
  });

  it('should test createByUserIdentity: invalid name: result null', function() {
    try {
      fakeAuthority._Domain = fakeDomain;
      var simplePrincipal = SimplePrincipal.createByUserIdentity(fakeDomain, '@@@@', fakeCreds, 0, fakeAuthority);

      expect(simplePrincipal).to.not.be.null;
      expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
      expect(simplePrincipal.getName()).to.equal('@@@@');
      expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
      expect(simplePrincipal.getIssueTime()).to.equal(0);
      expect(simplePrincipal.getAuthority()).to.not.be.null;
    } catch (e) {
      expect(1).to.be.false;
    }
  });

  it('should test createByUserIdentity: domain Null and authority null', function() {
    var simplePrincipal = SimplePrincipal.createByUserIdentity(null, fakeName, fakeCreds, 0, null);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.be.null;
    expect(simplePrincipal.getName()).to.equal(fakeName);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.be.null;
  });

   it('should test createByUserIdentity: no match domain to authority domain: result null', function() {
   var authority = new simplePrincipalMock('test');
   expect(SimplePrincipal.createByUserIdentity(fakeDomain, fakeName, fakeCreds, 0, authority)).to.be.null;
   });

  it('should test createByUserIdentity: authority Null: result null', function() {
    var simplePrincipal = SimplePrincipal.createByUserIdentity(fakeDomain, fakeName, fakeCreds, 0, null);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.equal(fakeDomain);
    expect(simplePrincipal.getName()).to.equal(fakeName);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.be.null;
  });

   it('should test createByUserIdentity: domain null: result null', function() {
   var authority = new simplePrincipalMock('test');
   expect(SimplePrincipal.createByUserIdentity(null, fakeName, fakeCreds, 0, authority)).to.be.null;
   });

  it('should test createByHostIdentity', function() {
    var simplePrincipal = SimplePrincipal.createByHostIdentity(fakeAppId, fakeCreds, fakeAuthority);

    expect(simplePrincipal).to.not.be.null;
    expect(simplePrincipal.getDomain()).to.be.null;
    expect(simplePrincipal.getName()).to.equal(fakeAppId);
    expect(simplePrincipal.getCredentials()).to.equal(fakeCreds);
    expect(simplePrincipal.getIssueTime()).to.equal(0);
    expect(simplePrincipal.getAuthority()).to.not.be.null;
  });

  it('should test set/getUnsignedCreds', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setUnsignedCreds(fakeUnsignedCreds);
    expect(simplePrincipal.getUnsignedCreds()).to.equal(fakeUnsignedCreds);
  });

  it('should test set/getAuthorizedService', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setAuthorizedService(fakeAuthorizedService);
    expect(simplePrincipal.getAuthorizedService()).to.equal(fakeAuthorizedService);
  });

  it('should test set/getIP', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setIP(fakeIP);
    expect(simplePrincipal.getIP()).to.equal(fakeIP);
  });

  it('should test set/getOriginalRequestor', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setOriginalRequestor(fakeOriginalRequestor);
    expect(simplePrincipal.getOriginalRequestor()).to.equal(fakeOriginalRequestor);
  });

  it('should test set/getKeyService', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setKeyService(fakeKeyService);
    expect(simplePrincipal.getKeyService()).to.equal(fakeKeyService);
  });

  it('should test set/getKeyId', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setKeyId(fakeKeyId);
    expect(simplePrincipal.getKeyId()).to.equal(fakeKeyId);
  });

  it('should test set/getX509Certificate', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    simplePrincipal.setX509Certificate(fakeCert);
    expect(simplePrincipal.getX509Certificate()).to.equal(fakeCert);
  });

  it('should test getFullName', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);

    expect(simplePrincipal.getFullName()).to.equal(fakeDomain + '.' + fakeName);
    expect(simplePrincipal.getFullName()).to.equal(fakeDomain + '.' + fakeName);

    simplePrincipal._fullName = null;
    simplePrincipal._name = null;
    expect(simplePrincipal.getFullName()).to.equal(fakeDomain);

    simplePrincipal._fullName = null;
    simplePrincipal._domain = null;
    simplePrincipal._name = fakeName;
    expect(simplePrincipal.getFullName()).to.equal(fakeName);

    simplePrincipal._fullName = null;
    simplePrincipal._domain = null;
    simplePrincipal._name = null;
    expect(simplePrincipal.getFullName()).to.be.null;
  });

  it('should test getFullName', function() {
    var simplePrincipal = SimplePrincipal.create(fakeDomain, fakeName, fakeCreds);
    expect(simplePrincipal.toString()).to.equal(fakeDomain + '.' + fakeName);

    simplePrincipal = SimplePrincipal.createByRoles(fakeDomain, fakeCreds, fakeRoles, fakeAuthority);
    expect(simplePrincipal.toString()).to.equal('ZToken_' + fakeDomain + '~' + fakeRoles.toString().replace('[', '').replace(']', ''));
  });
});
