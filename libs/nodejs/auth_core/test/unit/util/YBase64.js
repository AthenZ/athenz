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

var ybase64 = require('../../../src/util/YBase64');

var sinon = require('sinon');
var expect = require('chai').expect;
var sandbox;

var testMessage = 'testMessageToEncodeWithYBase64\n';

describe('YBase64 util', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should ybase64 string eqals test data', function() {
    expect(ybase64.ybase64Encode(testMessage)).to.equal('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--');
    expect(Buffer.from(testMessage).toString('base64').replace(/\+/g, '.').replace(/\//g, '_').replace(/=/g, '-')).to
      .equal('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--');
  });

  it('should string eqals ybase64 decoded test data', function() {
    expect(ybase64.ybase64Decode('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--').toString('UTF-8')).to.equal(testMessage);
    expect(ybase64.ybase64Decode('dGVzdE1lc3NhZ2VUb0VuY29kZVdpdGhZQmFzZTY0Cg--').toString('UTF-8')).to
      .equal(Buffer.from(ybase64.ybase64Encode(testMessage).replace(/\./g, '+').replace(/_/g, '/').replace(/-/g, '='), 'base64').toString());
  });

  it('should test ybase64Decode: invalid input: result error', function() {
    try {
      ybase64.ybase64Decode(123456789);
    } catch (e) {
      expect(e.message).to.be.contain('is not string');
      return;
    }
    expect(1).to.be.false;
  });

});
