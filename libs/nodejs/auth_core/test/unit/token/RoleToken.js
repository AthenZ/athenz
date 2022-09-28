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

var RoleToken = require('../../../src/token/RoleToken');

var fs = require('fs');
var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var signedToken = 'v=Z1;d=athenz.user;r=admin,users;c=1;p=test;h=test.athenz.com;proxy=proxyuser;a=01234abc;t=10000;e=30;k=0;i=172.168.0.1;s=signature';
var shortSignedToken = signedToken.replace(/t=.*?;/, '').replace(/e=.*?;/, '');
var tokenObject = {
  version: 'Z1',
  domain: 'athenz.user',
  roles: ['admin', 'users'],
  domainCompleteRoleSet: true,
  principal: 'test',
  host: 'test.athenz.com',
  proxyUser: 'proxyuser',
  salt: '01234abc',
  keyId: '0',
  ip: '172.168.0.1'
};

var privateKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var publicKey = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k0.pem', 'utf8'));
var publicKey01 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/public_k1.pem', 'utf8'));

describe('RoleToken impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test RoleToken: null: result error', function() {
    expect(function() {
      new RoleToken(null);
    }).to.throw(Error, 'Cannot read properties');
  });

  it('should test RoleToken: using signedToken', function() {
    var roleToken = new RoleToken(signedToken);

    expect(roleToken.getVersion()).to.equal('Z1');
    expect(roleToken.getDomain()).to.equal('athenz.user');
    expect(roleToken.getRoles()).to.deep.equal(['admin', 'users']);
    expect(roleToken.getDomainCompleteRoleSet()).to.be.true;
    expect(roleToken.getPrincipal()).to.equal('test');
    expect(roleToken.getHost()).to.equal('test.athenz.com');
    expect(roleToken.getIP()).to.equal('172.168.0.1');
    expect(roleToken.getKeyId()).to.equal('0');
    expect(roleToken.getProxyUser()).to.equal('proxyuser');
    expect(roleToken.getSalt()).to.equal('01234abc');
    expect(roleToken.getSignature()).to.equal('signature');

    expect(roleToken.getUnsignedToken()).to.equal('v=Z1;d=athenz.user;r=admin,users;c=1;p=test;h=test.athenz.com;proxy=proxyuser;a=01234abc;t=10000;e=30;k=0;i=172.168.0.1');
    expect(roleToken.getSignedToken()).to.equal('v=Z1;d=athenz.user;r=admin,users;c=1;p=test;h=test.athenz.com;proxy=proxyuser;a=01234abc;t=10000;e=30;k=0;i=172.168.0.1;s=signature');
  });

  it('should test RoleToken: using signedToken: signedToken Null: result error', function() {
    expect(function() {
      var roleToken = new RoleToken(signedToken);
      roleToken.parseSignedToken(null);
    }).to.throw(Error, 'Input String signedToken must not be empty');
  });

  it('should test RoleToken: using signedToken: domain Null: result error', function() {
    expect(function() {
      new RoleToken('v=Z1;r=admin,users;c=1;p=test;h=test.athenz.com;proxy=proxyuser;a=01234abc;t=10000;e=30;k=0;i=172.168.0.1;s=signature');
    }).to.throw(Error, 'SignedToken does not contain required domain component');
  });

  it('should test RoleToken: using signedToken: name Null: result error', function() {
    expect(function() {
      new RoleToken('v=Z1;d=athenz.user;c=1;p=test;h=test.athenz.com;proxy=proxyuser;a=01234abc;t=10000;e=30;k=0;i=172.168.0.1;s=signature');
    }).to.throw(Error, 'SignedToken does not contain required roles component');
  });

  it('should test RoleToken: using tokenObject', function() {
    var roleToken = new RoleToken(tokenObject);

    expect(roleToken.getVersion()).to.equal('Z1');
    expect(roleToken.getDomain()).to.equal('athenz.user');
    expect(roleToken.getRoles()).to.deep.equal(['admin', 'users']);
    expect(roleToken.getDomainCompleteRoleSet()).to.be.true;
    expect(roleToken.getPrincipal()).to.equal('test');
    expect(roleToken.getHost()).to.equal('test.athenz.com');
    expect(roleToken.getIP()).to.equal('172.168.0.1');
    expect(roleToken.getKeyId()).to.equal('0');
    expect(roleToken.getProxyUser()).to.equal('proxyuser');
    expect(roleToken.getSalt()).to.equal('01234abc');

    var unsignedToken = roleToken.getUnsignedToken().replace(/t=.*?;/, '').replace(/e=.*?;/, '');
    expect(unsignedToken + ';s=signature').to.equal(shortSignedToken);
  });

  it('should test RoleToken: using tokenObject with minimum params', function() {
    var tokenObj = Object.assign({}, tokenObject);
    delete tokenObj.domainCompleteRoleSet;
    delete tokenObj.salt;
    delete tokenObj.keyId;
    var roleToken = new RoleToken(tokenObj);

    expect(roleToken.getVersion()).to.equal('Z1');
    expect(roleToken.getDomain()).to.equal('athenz.user');
    expect(roleToken.getRoles()).to.deep.equal(['admin', 'users']);
    expect(roleToken.getDomainCompleteRoleSet()).to.be.false;
    expect(roleToken.getPrincipal()).to.equal('test');
    expect(roleToken.getHost()).to.equal('test.athenz.com');
    expect(roleToken.getIP()).to.equal('172.168.0.1');
    expect(roleToken.getKeyId()).to.equal('0');
    expect(roleToken.getProxyUser()).to.equal('proxyuser');
    expect(roleToken.getSalt()).to.be.a('String');

    var unsignedToken = roleToken.getUnsignedToken().replace(/t=.*?;/, '').replace(/e=.*?;/, '').replace(/a=.*?;/, '');
    expect(unsignedToken + ';s=signature').to.equal(shortSignedToken.replace(/c=.*?;/, '').replace(/a=.*?;/, ''));
  });

  it('should test RoleToken: using tokenObject: version Null: result error', function() {
    expect(function() {
      var tokenObj = Object.assign({}, tokenObject);
      delete tokenObj.version;
      new RoleToken(tokenObj);
    }).to.throw(Error, 'version, domain and roles parameters must not be null.');
  });

  it('should test RoleToken: using tokenObject: domain Null: result error', function() {
    expect(function() {
      var tokenObj = Object.assign({}, tokenObject);
      delete tokenObj.domain;
      var roleToken = new RoleToken(tokenObj);
    }).to.throw(Error, 'version, domain and roles parameters must not be null.');
  });

  it('should test RoleToken: using tokenObject: name Null: result error', function() {
    var tokenObj1 = Object.assign({}, tokenObject);
    var tokenObj2 = Object.assign({}, tokenObject);
    var roleToken;
    tokenObj1.roles = [];
    delete tokenObj2.roles;

    expect(function() {
      new RoleToken(tokenObj1);
    }).to.throw(Error, 'version, domain and roles parameters must have values.');
    expect(function() {
      new RoleToken(tokenObj2);
    }).to.throw(Error, 'version, domain and roles parameters must not be null.');
  });
});
