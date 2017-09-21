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
  identity: null
};

var domainName = 'athenz.user';
var serviceName = 'test';

var siaMock = new siaProviderMock(domainName, serviceName);
var ideMock = new identityMock(domainName, serviceName);

var siaParams = {
  domainName: domainName,
  serviceName: serviceName,
  siaProvider: siaMock,
  identity: null
};

var cacheKey = 'cacheKeyRoleToken';

describe('ZPEMatch', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test ZPEMatch equalMatches', function() {
    var zpeMatch = ZPEMatch('athenz.test.aaa');
    expect(zpeMatch.equal.matches('athenz.test.aaa')).to.equal(true);
    zpeMatch = ZPEMatch('athenz.test.aaa');
    expect(zpeMatch.equal.matches('athenz.test.bbb')).to.equal(false);
  });

  it('should test ZPEMatch startswithMatches', function() {
    var zpeMatch = ZPEMatch('athenz');
    expect(zpeMatch.startswith.matches('athenz.test.aaa')).to.equal(true);
    zpeMatch = ZPEMatch('aaa');
    expect(zpeMatch.startswith.matches('athenz.test.aaa')).to.equal(false);
  });

  it('should test ZPEMatch allMatches', function() {
    var zpeMatch = ZPEMatch('anything');
    expect(zpeMatch.all.matches('athenz.test.aaa')).to.equal(true);
  });

  it('should test ZPEMatch regexMatches', function() {
    var zpeMatch = ZPEMatch(/[a-z]/);
    expect(zpeMatch.regex.matches('athenz.test.aaa')).to.equal(true);
    zpeMatch = ZPEMatch(/[A-z]/);
    expect(zpeMatch.regex.matches('athenz.test.aaa')).to.equal(true);
    zpeMatch = ZPEMatch(/[A-Z]/);
    expect(zpeMatch.regex.matches('athenz.test.aaa')).to.equal(false);
  });
});
