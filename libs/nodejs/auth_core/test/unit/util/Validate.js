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

var validate = require('../../../src/util/Validate');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

describe('Validate util', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should validate principal name', function() {
    expect(validate.principalName('user:john%doe')).to.equal(false);
    expect(validate.principalName('user.user:john.doe.')).to.equal(false);
    expect(validate.principalName('user.user.:john.doe')).to.equal(false);
    expect(validate.principalName('.user:doe')).to.equal(false);
    expect(validate.principalName('.doe')).to.equal(false);
    expect(validate.principalName(':doe')).to.equal(false);
    expect(validate.principalName('doe:')).to.equal(false);
    expect(validate.principalName('::doe')).to.equal(false);
    expect(validate.principalName('doe::')).to.equal(false);
    expect(validate.principalName('user:john:doe')).to.equal(false);

    expect(validate.principalName('user:doe')).to.equal(true);
    expect(validate.principalName('user:doe')).to.equal(true);
    expect(validate.principalName('user:john.doe')).to.equal(true);
    expect(validate.principalName('user.user:doe')).to.equal(true);
    expect(validate.principalName('user.user:john.doe')).to.equal(true);
    expect(validate.principalName('user:john_doe')).to.equal(true);
    expect(validate.principalName('john-doe')).to.equal(true);
    expect(validate.principalName('user:john-doe')).to.equal(true);
  });

  it('should validate domain name', function() {
    expect(validate.domainName('domain$sub')).to.equal(false);
    expect(validate.domainName('coretech:domain')).to.equal(false);
    expect(validate.domainName('55')).to.equal(false);
    expect(validate.domainName('3com.gov')).to.equal(false);

    expect(validate.domainName('domain')).to.equal(true);
    expect(validate.domainName('domain.sub.sub')).to.equal(true);
    expect(validate.domainName('domain_')).to.equal(true);
    expect(validate.domainName('_')).to.equal(true);
    expect(validate.domainName('_test._')).to.equal(true);
    expect(validate.domainName('sub1_sub2')).to.equal(true);
    expect(validate.domainName('sub1_sub2_sub3')).to.equal(true);
    expect(validate.domainName('sub1_sub2.sub3_sub4')).to.equal(true);
    expect(validate.domainName('sub1_sub2_.sub3_sub4_')).to.equal(true);
    expect(validate.domainName('sub1_sub2_.sub3_sub4_-')).to.equal(true);
    expect(validate.domainName('domain-part')).to.equal(true);
    expect(validate.domainName('com-test.gov')).to.equal(true);
  });
});
