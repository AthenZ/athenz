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

var ZPEMatch = require('../../src/ZPEMatch');

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
    domainName: domainName,
    serviceName: serviceName,
    siaProvider: siaMock,
    identity: null,
};

var cacheKey = 'cacheKeyRoleToken';

describe('ZPEMatch completely match', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it('should test ZPEMatch equalMatches', function () {
        var zpeMatch = ZPEMatch('athenz.test.aaa');
        expect(zpeMatch.equal.matches('athenz.test.aaa')).to.equal(true);
        zpeMatch = ZPEMatch('athenz.test.aaa');
        expect(zpeMatch.equal.matches('athenz.test.bbb')).to.equal(false);
    });
});

describe('ZPEMatch check * (Any charactor wildcard option)', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it("startswith 'aaa*' matches 'aaabbb'", function () {
        var zpeMatch = ZPEMatch('aaa*');
        expect(zpeMatch.startswith.matches('aaabbb')).to.equal(true);
    });

    it("startswith 'bbb*' un-matches 'aaabbb'", function () {
        var zpeMatch = ZPEMatch('bbb*');
        expect(zpeMatch.startswith.matches('aaabbb')).to.equal(false);
    });

    it("regex '*bbb' matches 'aaabbb'", function () {
        var zpeMatch = ZPEMatch('*bbb');
        expect(zpeMatch.regex.matches('aaabbb')).to.equal(true);
    });

    it("regex '*bbb' un-matches 'bbbaaa'", function () {
        var zpeMatch = ZPEMatch('*bbb');
        expect(zpeMatch.regex.matches('bbbaaa')).to.equal(false);
    });

    it("all '*' matches ''(empty string)", function () {
        var zpeMatch = ZPEMatch('*');
        expect(zpeMatch.all.matches('')).to.equal(true);
    });

    it("all '*' matches 'thisistest'", function () {
        var zpeMatch = ZPEMatch('*');
        expect(zpeMatch.all.matches('thisistest')).to.equal(true);
    });

    it("regex 'aaa*bbb' matches 'aaaxxxbbb'", function () {
        var zpeMatch = ZPEMatch('aaa*bbb');
        expect(zpeMatch.regex.matches('aaaxxxbbb')).to.equal(true);
    });

    it("regex 'aaa*bbb' un-matches 'aaxxxbbb'", function () {
        var zpeMatch = ZPEMatch('aaa*bbb');
        expect(zpeMatch.regex.matches('aaxxxbbb')).to.equal(false);
    });
});

describe('ZPEMatch check ? (Single charactor wildcard option)', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it("regex 'aaa?' matches 'aaab'", function () {
        var zpeMatch = ZPEMatch('aaa?');
        expect(zpeMatch.regex.matches('aaab')).to.equal(true);
    });

    it("regex 'bbb?' un-matches 'abbb'", function () {
        var zpeMatch = ZPEMatch('bbb?');
        expect(zpeMatch.regex.matches('abbb')).to.equal(false);
    });

    it("regex '?bbb' matches 'abbb'", function () {
        var zpeMatch = ZPEMatch('?bbb');
        expect(zpeMatch.regex.matches('abbb')).to.equal(true);
    });

    it("regex '?bbb' un-matches 'bbba'", function () {
        var zpeMatch = ZPEMatch('?bbb');
        expect(zpeMatch.regex.matches('bbba')).to.equal(false);
    });

    it("regex '?' un-matches ''(empty string)", function () {
        var zpeMatch = ZPEMatch('?');
        expect(zpeMatch.regex.matches('')).to.equal(false);
    });

    it("regex 'aaa?bbb' matches 'aaaxbbb'", function () {
        var zpeMatch = ZPEMatch('aaa?bbb');
        expect(zpeMatch.regex.matches('aaaxbbb')).to.equal(true);
    });

    it("regex 'aaa?bbb' un-matches 'aaxbbb'", function () {
        var zpeMatch = ZPEMatch('aaa?bbb');
        expect(zpeMatch.regex.matches('aaxbbb')).to.equal(false);
    });
});

describe('ZPEMatch check regex meta symbol', function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it("regex 'aaa.' un-matches 'aaaa'", function () {
        var zpeMatch = ZPEMatch('aaa.');
        expect(zpeMatch.regex.matches('aaaa')).to.equal(false);
    });

    const metaSymbols = ['\\', '^', '$', '.', '|', '[', '+', '(', ')', '{'];
    metaSymbols.forEach((meta) => {
        it(`check meta symbol ${meta} is escaped`, function () {
            var zpeMatch = null;
            metaSymbols.forEach((meta) => {
                zpeMatch = ZPEMatch(`aaa${meta}`);
                expect(zpeMatch.regex.matches(`aaa${meta}`)).to.equal(true);
            });
        });
    });
});

describe("ZPEMatch adds implicitly '^' and '$' to enable strict matches", function () {
    beforeEach(function () {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function () {
        sandbox.restore();
    });

    it("regex 'a?b' matches 'aab'", function () {
        var zpeMatch = ZPEMatch('a?b');
        expect(zpeMatch.regex.matches('aab')).to.equal(true);
    });

    it("regex 'a?b' un-matches 'aaab'", function () {
        var zpeMatch = ZPEMatch('a?b');
        expect(zpeMatch.regex.matches('aaab')).to.equal(false);
    });

    it("regex 'a?b' un-matches 'abbb'", function () {
        var zpeMatch = ZPEMatch('a?b');
        expect(zpeMatch.regex.matches('abbb')).to.equal(false);
    });
});
