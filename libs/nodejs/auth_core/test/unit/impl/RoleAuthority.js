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

var RoleAuthority = require('../../../src/impl/RoleAuthority');
var RoleToken = require('../../../src/token/RoleToken');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var privateKeyK0 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k0.pem', 'utf8'));
var privateKeyK1 = Buffer.from(fs.readFileSync(process.cwd() + '/test/resources/unit_test_private_k1.pem', 'utf8'));

var keyStore = require('../../config/KeyStore');

var tokenObject = {
  version: 'Z1',
  domain: 'athenz.provider',
  roles: ['role1', 'role2'],
  principal: 'ahtenz.tenant.service',
  host: 'test.athenz.com',
  keyId: '0',
  ip: '172.168.0.1',
  salt: '01234abc',
  expiryTime: 30 * 24 * 60 * 60,
};

var remoteAddr = '172.168.0.1';

describe('RoleAuthority impl', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test RoleAuthority', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority._allowedOffset).to.be.a('number');
    expect(roleAuthority._userDomain).to.be.a('string');
    expect(roleAuthority._headerName).to.be.a('string');
  });

  it('should test initialize', function() {
    var roleAuthority = new RoleAuthority();

    roleAuthority.initialize();
  });

  it('should test getDomain', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority.getDomain()).to.equal('sys.auth');
  });

  it('should test getHeader', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority.getHeader()).to.be.a('string');
  });

  it('should test authenticate', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    var roleToken = new RoleToken(tokenObject);
    roleToken.sign(privateKeyK0);

    expect(roleAuthority.authenticate(roleToken.getSignedToken(), remoteAddr, 'PUT')).to.not.be.null;
  });

  it('should test authenticate: signedToken Null: result null', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    expect(roleAuthority.authenticate(null, remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: validate false: result null', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    var roleToken = new RoleToken(tokenObject);
    roleToken.sign(privateKeyK1);

    expect(roleAuthority.authenticate(roleToken.getSignedToken(), remoteAddr, 'PUT')).to.be.null;
  });

  it('should test authenticate: token principal has no domain: result null', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    var tokenObj = Object.assign({}, tokenObject);
    tokenObj.principal = 'principal';

    var roleToken = new RoleToken(tokenObj);
    roleToken.sign(privateKeyK0);

    expect(roleAuthority.authenticate(roleToken.getSignedToken(), '172.168.0.2', 'PUT')).to.be.null;
  });

  it('should test authenticate: IP Mismatch: result error', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    var tokenObj = Object.assign({}, tokenObject);
    tokenObj.principal = 'user.xxx';

    var roleToken = new RoleToken(tokenObj);
    roleToken.sign(privateKeyK0);

    expect(roleAuthority.authenticate(roleToken.getSignedToken(), '172.168.0.2', 'PUT')).to.be.null;
  });

  it('should test _isWriteOperation: httpMethod Null: result false', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority._isWriteOperation(null)).to.be.false;
  });

  it('should test _isWriteOperation: httpMethod PUT POST DELETE', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority._isWriteOperation('PUT')).to.be.true;
    expect(roleAuthority._isWriteOperation('POST')).to.be.true;
    expect(roleAuthority._isWriteOperation('DELETE')).to.be.true;
  });

  it('should test _isWriteOperation: invalid httpMethod: result false', function() {
    var roleAuthority = new RoleAuthority();

    expect(roleAuthority._isWriteOperation('GET')).to.be.false;
  });

  it('should test setKeyStore', function() {
    var roleAuthority = new RoleAuthority();
    roleAuthority.setKeyStore(keyStore);

    expect(roleAuthority._keyStore).to.not.be.null;
  });
});
