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

var SimpleServiceIdentityProvider = require('../../../src/impl/SimpleServiceIdentityProvider');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;
var fs = require('fs');

var domain = 'athenz.user';
var service = 'test';
var keyId = '0';
var privateKeyK0 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));


describe('SimpleServiceIdentityProvider impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test SimpleServiceIdentityProvider', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);

    expect(simServiceProvider._domain).to.equal(domain);
    expect(simServiceProvider._service).to.equal(service);
    expect(simServiceProvider._key).to.equal(privateKeyK0);
    expect(simServiceProvider._tokenTimeout).to.equal(3600);
    expect(simServiceProvider._keyId).to.equal(keyId);
    expect(simServiceProvider._host).to.be.a('string');
  });

  it('should test getIdentity', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    var princ = simServiceProvider.getIdentity(domain, service);

    expect(princ).to.not.be.null;
    expect(princ.getDomain()).to.equal(domain);
    expect(princ.getName()).to.equal(service);
    expect(princ.getCredentials()).to.be.a('string');
    expect(princ.getCredentials().indexOf('undefined') === -1).to.be.true;

    expect(princ.getIssueTime()).to.be.a('number');
    expect(princ.getIssueTime().toString().indexOf('.') === -1).to.be.true;

    expect(princ.getUnsignedCreds()).to.be.a('string');
    expect(princ.getUnsignedCreds().indexOf('undefined') === -1).to.be.true;

    expect(princ.getIP()).to.be.null;
    expect(princ.getKeyService()).to.be.null;
    expect(princ.getAuthorizedService()).to.be.null;
    expect(princ.getOriginalRequestor()).to.be.null;
    expect(princ.getKeyId()).to.be.null;
    expect(princ.getX509Certificate()).to.be.null;
  });

  it('should test getIdentity: no match domainName: result null', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    expect(simServiceProvider.getIdentity('test', service)).to.be.null;
  });

  it('should test getIdentity: no match serviceName: result null', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    expect(simServiceProvider.getIdentity(domain, 'athenz')).to.be.null;
  });

  it('should test _getServerHostName', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    expect(simServiceProvider._getServerHostName()).to.not.be.null;
  });

  it('should test set/getHost', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    simServiceProvider.setHost('athenz.com');
    expect(simServiceProvider.getHost()).to.equal('athenz.com');
  });

  it('should test setTokenTimeout', function() {
    var simServiceProvider = new SimpleServiceIdentityProvider(domain, service, privateKeyK0, keyId);
    simServiceProvider.setTokenTimeout(4800);
    expect(simServiceProvider._tokenTimeout).to.equal(4800);
  });
});
