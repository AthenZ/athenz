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

var PublicKeyStore = require('../../src/PublicKeyStore');
var YBase64 = require('@athenz/auth-core').YBase64;

var sinon = require('sinon');
var expect = require('chai').expect;
var cache = require('memory-cache');

var sandbox;

var policyDir = process.cwd() + '/test/resources/pol';
var confFileName = process.cwd() + '/test/resources/athenz.conf';
PublicKeyStore.setConfig({
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

describe('PublicKeyStore', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        PublicKeyStore.setConfig({
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

    it('should test PublicKeyStore constructor', function () {
        var publicKeyStore = new PublicKeyStore();
        expect(publicKeyStore._zmsPublicKeyMap[0]).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
        expect(publicKeyStore._ztsPublicKeyMap[0]).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
    });

    it('should test PublicKeyStore fails', function () {
        PublicKeyStore.setConfig({
            zpeClient: {
                logLevel: 'debug',
                policyDir: policyDir,
                confFileName: null,
                tokenRefresh: 1800,
                policyRefresh: 1800,
                allowedOffset: 300,
                disableCache: false,
                updater: './ZPEUpdater',
                disableWatch: true,
            },
        });
        var publicKeyStore;
        expect(function () {
            publicKeyStore = new PublicKeyStore();
        }).to.throw(
            Error,
            "ENOENT: no such file or directory, open '/home/athenz/conf/athenz/athenz.conf'"
        );
        expect(publicKeyStore).to.be.undefined;
    });

    it('should test PublicKeyStore fails with empty key', function () {
        PublicKeyStore.setConfig({
            zpeClient: {
                logLevel: 'debug',
                policyDir: policyDir,
                confFileName:
                    process.cwd() + '/test/resources/athenz.empty.conf',
                tokenRefresh: 1800,
                policyRefresh: 1800,
                allowedOffset: 300,
                disableCache: false,
                updater: './ZPEUpdater',
                disableWatch: true,
            },
        });
        var publicKeyStore = new PublicKeyStore();
        expect(publicKeyStore._zmsPublicKeyMap[0]).to.be.undefined;
        expect(publicKeyStore._ztsPublicKeyMap[0]).to.be.undefined;

        PublicKeyStore.setConfig({
            zpeClient: {
                logLevel: 'debug',
                policyDir: policyDir,
                confFileName:
                    process.cwd() +
                    '/test/resources/athenz.empty.publickey.conf',
                tokenRefresh: 1800,
                policyRefresh: 1800,
                allowedOffset: 300,
                disableCache: false,
                updater: './ZPEUpdater',
                disableWatch: true,
            },
        });
        publicKeyStore = new PublicKeyStore();
        expect(publicKeyStore._zmsPublicKeyMap[0]).to.be.undefined;
        expect(publicKeyStore._ztsPublicKeyMap[0]).to.be.undefined;
    });

    it('should test PublicKeyStore getZtsKey', function () {
        var publicKeyStore = new PublicKeyStore();
        expect(publicKeyStore.getZtsKey('0')).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
        expect(publicKeyStore.getZtsKey('1')).to.be.undefined;
        expect(publicKeyStore.getZtsKey()).to.be.null;
    });

    it('should test PublicKeyStore getZmsKey', function () {
        var publicKeyStore = new PublicKeyStore();
        expect(publicKeyStore.getZmsKey('0')).to.deep.equal(
            YBase64.ybase64Decode(
                'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFzdXBTOVJrUFQvMDdEcEVLUjZpRQp2Umh4S0NDQ0JlQUFnU3hJcHk3MUhqOHZkU21hNUdQTktpYUthczBOaVdpUXRCZW9OYTZia1NabE04bE9Sb1BwCjFzSy9uUjVCSWRwTjdWZ0NrWEdtSjY5THJmYm44ODdHWjBPV0tFZFlKcXI0S2tpMktHOFFzYTgxNXE4ei9LRk4KRjg4NjlqYzRRbDdkVnY3NUZDays4SXNJcnBCZ3I1eU1RTnZNb24xYmY4MUZka0lJdE9iUnZIMm9NeHZLQVRqVworRUpvcytTbENITmQreDR1WUM5bE40SGk2cXFKTWNBZ3I0aTRhM0JNV2pHSk1DclY3UWpibzcwOW1jS2JqUE9JCmwvMEs3YjczZ2ZhSEZCZnBmaXFlanNsa2xab3VoSUhvdWxoZk93dXdSZStmMW14UkpsWmlhMjh6K29VZEVYSVUKZlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg--'
            )
        );
        expect(publicKeyStore.getZmsKey('1')).to.be.undefined;
        expect(publicKeyStore.getZmsKey()).to.be.null;
    });
});
