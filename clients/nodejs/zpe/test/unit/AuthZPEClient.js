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

var AuthZPEClient = require('../../src/AuthZPEClient');

var RoleToken = require('@athenz/auth-core').RoleToken;
var YBase64 = require('@athenz/auth-core').YBase64;

var privateKeyK0 = new Buffer(fs.readFileSync(process.cwd() + '/test/resources/private_k0.pem', 'utf8'));
var policyDir = process.cwd() + '/test/resources/pol';
var confFileName = process.cwd() + '/test/resources/athenz.conf';

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

AuthZPEClient.setConfig({
  zpeClient: {
    logLevel: 'debug',
    policyDir: policyDir,
    confFileName: confFileName,
    tokenRefresh: 1800,
    policyRefresh: 1800,
    allowedOffset: 300,
    disableCache: false
  }
});

var roleTokenParams = {
  version: 'Z1',
  domain: 'athenz.test',
  roles: ['users']
};
var rToken = new RoleToken(roleTokenParams);
rToken.sign(privateKeyK0);
var roleToken = rToken.getSignedToken();
var resource = 'athenz.test:testresgroup.allow';
var action = 'read';

describe('AuthZPEClient', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test AuthZPEClient getZmsPublicKey', function() {
    expect(AuthZPEClient.getZmsPublicKey('0')).to.deep.equal(YBase64.ybase64Decode('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3V2ZNcU9KQTJLbFBPVW1Fa1F2SworcU9BbGFiNkZ5aUtvQTkwcnBxTldPRDAyV2x3eHpZcWtFTDBtbFQ4NWUzQzBUViszVzRwM2Vkci9TS285ZDdzCk9GQ1k3NUpTM0V4eFQrU3ZobHA2M2lSdCtuOHVleE1LUk5tRnBlTkczYUZ0RHpqUFR2Y2o0TEJCOVl0UjRsb0QKbVY0WVA1aUpFbU5pSENkYXVocVBvWGZNMldDNXZub0NrUUZ4WWExQkh4UWt1TXNQQzdBWjUrUjdqRDdKMnN2KwpUMlF5UWxjNGl4ZXlZY0VWZHhxdUE0cW9vRVRGTnVuS1hnaWZPbFdYM3JYOVQ1WDhJODNEUUY2VnB3VHorckhGCmFydDVacUlZd1NhS1BETkhjRWZaZldOOVZHZk5DNDdEZWpXOWNUTURRRmZVdUViMG02WEViajEyNnplZVloTFYKaVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'));
  });

  it('should test AuthZPEClient getZtsPublicKey', function() {
    expect(AuthZPEClient.getZtsPublicKey('0')).to.deep.equal(YBase64.ybase64Decode('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxY2N0QnhzbXRGZ0NSV3drLzF2NgpnVURCTmRTa1RRUkg2UDM5ejU1bVEyQ09USHdlTW5BZG0yQ1hQMm56RHV5dnVjaHdpOENnaVFEMUdnMzdBN2ZPCjZCVCt1NkgxaGJnU0t4NnphQ1pXRGg1NkEwOUtvUTdTVEN4cFVQUkgvZmFobGVuNDU2d2pWejQyMjVndG1NcWsKbU96cHYyZWZqenFnQUYxVWhnWWRwRTUwNDZjMGVKSGIwdWtHUmZvcytkZWVtbFdZL3VmZTBrUnAxQUd0RzVrNQp4aXN0YjVLdW9TL1JJTG1NK3NzbWhqR1FSS3ZiZG9QTkowQTdXeHJ1akYxVTVldFp3NFdKK1FCMnNpeVVRdXhvClY0bUQ2cjNia0U1S0Z3UWlXV2NjaWpUN2J4Mmw0NER1dUU2YjhTbUovajRvNVdDS3pXNjJhWGE5aklnUjRDcjkKS3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'));
  });

  it('should test AuthZPEClient stripDomainPrefix', function() {
    expect(AuthZPEClient.stripDomainPrefix('athenz.test:resource', 'athenz.test', 'defaultDomain')).to.equal('resource');
  });

  /*
    ALLOW: "Access Check was explicitly allowed",
    DENY: "Access Check was explicitly denied",
    DENY_NO_MATCH: "Access denied due to no match to any of the assertions defined in domain policy file",
    DENY_ROLETOKEN_EXPIRED: "Access denied due to expired RoleToken",
    DENY_ROLETOKEN_INVALID: "Access denied due to invalid RoleToken",
    DENY_DOMAIN_MISMATCH: "Access denied due to domain mismatch between Resource and RoleToken",
    DENY_DOMAIN_NOT_FOUND: "Access denied due to domain not found in library cache",
    DENY_DOMAIN_EXPIRED: "Access denied due to expired domain policy file",
    DENY_DOMAIN_EMPTY: "Access denied due to no policies in the domain file",
    DENY_INVALID_PARAMETERS: "Access denied due to invalid/empty action/resource values",
  */
  it('should test AuthZPEClient allowAccess expecting result ALLOW', function() {
    AuthZPEClient.allowAccess(
      {
        roleToken: roleToken,
        resource: resource,
        action: action
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access Check was explicitly allowed');
      }
    );
  });

  it('should test AuthZPEClient allowAccess expecting result DENY', function() {
    AuthZPEClient.allowAccess(
      {
        roleToken: roleToken,
        resource: 'athenz.test:testresgroup.deny',
        action: 'write'
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access Check was explicitly denied');
      }
    );
  });

  it('should test AuthZPEClient allowAccess expecting result DENY_NO_MATCH', function() {
    AuthZPEClient.allowAccess(
      {
        roleToken: roleToken,
        resource: 'athenz.test:nosuchresource',
        action: action
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access denied due to no match to any of the assertions defined in domain policy file');
      }
    );
  });

  it('should test AuthZPEClient allowAccess expecting result DENY_ROLETOKEN_INVALID', function() {
    AuthZPEClient.allowAccess(
      {
        roleToken: 'v=Z1;d=athenz.test;r=users',
        resource: 'athenz.test:nosuchresource',
        action: action
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access denied due to invalid RoleToken');
      }
    );
  });

  it('should test AuthZPEClient allowAccess expecting result DENY_DOMAIN_MISMATCH', function() {
    var roleTokenParams = {
      version: 'Z1',
      domain: 'athenz.test.nosuchdomain',
      roles: ['users']
    };
    var rToken = new RoleToken(roleTokenParams);
    rToken.sign(privateKeyK0);
    var roleToken = rToken.getSignedToken();
    AuthZPEClient.allowAccess(
      {
        roleToken: roleToken,
        resource: resource,
        action: action
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access denied due to domain mismatch between Resource and RoleToken');
      }
    );
  });

  it('should test AuthZPEClient allowAccess expecting result DENY_DOMAIN_NOT_FOUND', function() {
    var roleTokenParams = {
      version: 'Z1',
      domain: 'athenz.test.nosuchdomain',
      roles: ['users']
    };
    var rToken = new RoleToken(roleTokenParams);
    rToken.sign(privateKeyK0);
    var roleToken = rToken.getSignedToken();
    AuthZPEClient.allowAccess(
      {
        roleToken: roleToken,
        resource: 'athenz.test.nosuchdomain:testresgroup.allow',
        action: action
      },
      (err, accessCheckStatus) => {
        expect(accessCheckStatus).to.deep.equal('Access denied due to domain not found in library cache');
      }
    );
  });
});
