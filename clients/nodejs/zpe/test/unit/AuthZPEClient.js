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

var privateKeyK0 = Buffer.from(
    fs.readFileSync(
        process.cwd() + '/test/resources/unit_test_private_k0.pem',
        'utf8'
    )
);
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
        disableCache: false,
        updater: './ZPEUpdater',
        disableWatch: true,
    },
});

// RoleTokens
var roleTokenParams = {
    version: 'Z1',
    domain: 'athenz.test',
    roles: ['users'],
};
var rToken = new RoleToken(roleTokenParams);
rToken.sign(privateKeyK0);
var roleToken = rToken.getSignedToken();

var wildcardRoleTokenParams = {
    version: 'Z1',
    domain: 'athenz.test',
    roles: ['wildcardroletest'],
};
var wildcardRToken = new RoleToken(wildcardRoleTokenParams);
wildcardRToken.sign(privateKeyK0);
var wildcardRoleToken = wildcardRToken.getSignedToken();

var noSuchRoleTokenParams = {
    version: 'Z1',
    domain: 'athenz.test',
    roles: ['nosuchrole'],
};
var nRToken = new RoleToken(noSuchRoleTokenParams);
nRToken.sign(privateKeyK0);
var noSuchRoleToken = nRToken.getSignedToken();

var emptyRoleTokenParams = {
    version: 'Z1',
    domain: 'athenz.test.empty',
    roles: ['users'],
};
var eRToken = new RoleToken(emptyRoleTokenParams);
eRToken.sign(privateKeyK0);
var emptyRoleToken = eRToken.getSignedToken();

var expiredRoleTokenParams = {
    version: 'Z1',
    domain: 'athenz.test',
    roles: ['users'],
};
var expiredRToken = new RoleToken(
    'v=Z1;d=athenz.test;r=users;a=2fff22fa;t=1521813351;e=1521813351;k=0;s=dummy'
);
expiredRToken.sign(privateKeyK0);
var expiredRoleToken = expiredRToken.getSignedToken();
console.log(expiredRoleToken);
// RoleTokens

describe('AuthZPEClient', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        AuthZPEClient.setConfig({
            zpeClient: {
                logLevel: 'debug',
                policyDir: policyDir,
                confFileName: confFileName,
                tokenRefresh: 1800,
                policyRefresh: 1800,
                allowedOffset: 300,
                disableCache: false,
                updater: './ZPEUpdater',
                disableWatch: true,
            },
        });
        sandbox.restore();
    });

    it('should test AuthZPEClient getZmsPublicKey', function () {
        expect(AuthZPEClient.getZmsPublicKey('0')).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
    });

    it('should test AuthZPEClient getZtsPublicKey', function () {
        expect(AuthZPEClient.getZtsPublicKey('0')).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
    });

    it('should test AuthZPEClient stripDomainPrefix', function () {
        expect(
            AuthZPEClient.stripDomainPrefix(
                'athenz.test:resource',
                'athenz.test',
                'defaultDomain'
            )
        ).to.equal('resource');
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
    it('should test AuthZPEClient allowAccess expecting result ALLOW (Begin-with match)', function () {
        var resource = 'athenz.test:testresgroup.allow';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );

        resource = 'athenz.test:testresgroup.allow';
        action = 'readandwrite';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );

        resource = 'athenz.test:testresgroup.allow';
        action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: wildcardRoleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );
    });

    it('should test authzpeclient allowaccess expecting result deny with dot (begin-with match)', function () {
        //var resource = 'athenz.test:testresgroup.';
        var resource = 'athenz.test:testresgroupa';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to no match to any of the assertions defined in domain policy file'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result ALLOW (End-with match)', function () {
        var resource = 'allow.testresgroup';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result ALLOW', function () {
        var resource = 'allow.testresgroup';
        var action = 'read';
        AuthZPEClient.setConfig({
            zpeClient: {
                logLevel: 'debug',
                policyDir: policyDir,
                confFileName: confFileName,
                tokenRefresh: 1800,
                policyRefresh: 1800,
                allowedOffset: 300,
                disableCache: false,
                updater: './ZPEUpdater',
                disableWatch: false,
            },
        });
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY', function () {
        var resource = 'athenz.test:testresgroup.deny';
        var action = 'write';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly denied'
                );
            }
        );

        resource = 'athenz.test:testresgroup.deny';
        action = 'write';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly denied'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_NO_MATCH', function () {
        var resource = 'athenz.test:nosuchresource';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to no match to any of the assertions defined in domain policy file'
                );
            }
        );

        resource = 'allow.testresgroup';
        action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: noSuchRoleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to no match to any of the assertions defined in domain policy file'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_DOMAIN_EMPTY', function () {
        var resource = 'allow.testresgroup';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: emptyRoleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to no policies in the domain file'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_ROLETOKEN_EXPIRED', function () {
        var resource = 'allow.testresgroup';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: expiredRoleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to expired RoleToken'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_ROLETOKEN_INVALID', function () {
        var resource = 'athenz.test:nosuchresource';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: 'v=Z1;d=athenz.test;r=users',
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to invalid RoleToken'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_DOMAIN_MISMATCH', function () {
        var resource = 'athenz.test:testresgroup.allow';
        var action = 'read';
        var roleTokenParams = {
            version: 'Z1',
            domain: 'athenz.test.nosuchdomain',
            roles: ['users'],
        };
        var rToken = new RoleToken(roleTokenParams);
        rToken.sign(privateKeyK0);
        var roleToken = rToken.getSignedToken();
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to domain mismatch between Resource and RoleToken'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_DOMAIN_NOT_FOUND', function () {
        var resource = 'athenz.test.nosuchdomain:testresgroup.allow';
        var action = 'read';
        var roleTokenParams = {
            version: 'Z1',
            domain: 'athenz.test.nosuchdomain',
            roles: ['users'],
        };
        var rToken = new RoleToken(roleTokenParams);
        rToken.sign(privateKeyK0);
        var roleToken = rToken.getSignedToken();
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to domain not found in library cache'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result DENY_INVALID_PARAMETERS', function () {
        var resource = '';
        var action = 'read';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to invalid/empty action/resource values'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result allow with asterisk (two asterisk match)', function () {
        var resource = 'athenz.test:testresgroup';
        var action = 'XXXreadXXX';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result allow with ? (question mark)', function () {
        var resource = 'athenz.test:testresgroup.a';
        var action = 'get';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access Check was explicitly allowed'
                );
            }
        );
    });

    it('should test AuthZPEClient allowAccess expecting result deny with ? (question mark)', function () {
        var resource = 'athenz.test:testresgroup.toolong';
        var action = 'get';
        AuthZPEClient.allowAccess(
            {
                roleToken: roleToken,
                resource: resource,
                action: action,
            },
            (err, accessCheckStatus) => {
                expect(accessCheckStatus).to.deep.equal(
                    'Access denied due to no match to any of the assertions defined in domain policy file'
                );
            }
        );
    });
});
