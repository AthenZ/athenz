/**
 * Copyright 2016 Yahoo Inc.
 *
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

var commonApi = require('../../../src/api/common');

var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox,
  req,
  res;

describe('common api', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
    req = {
      restClient: {
        getDomainList: function() {}
      }
    };
    res = {
      locals: {}
    };
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('getPageCommonData', function() {
    it('should handle all success case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getDomainList').callsArgWith(0, null, {names: ['a']});

      var cb = sandbox.spy();

      commonApi.getPageCommonData(req, res, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal(null);
      expect(res.locals.domains).to.deep.equal(['a']);

      restMock.verify();
    });

    it('should handle get domainList error case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getDomainList').callsArgWith(0, 'err');

      var cb = sandbox.spy();

      commonApi.getPageCommonData(req, res, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal(null);
      expect(res.locals.domains).to.deep.equal([]);

      restMock.verify();
    });
  });
});
