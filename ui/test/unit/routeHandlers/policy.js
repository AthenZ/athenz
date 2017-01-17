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

var policyHandler = require('../../../src/routeHandlers/policy');

var sinon = require('sinon');
var expect = require('chai').expect;

var req = require('../../config/helpers').req;
var res = require('../../config/helpers').res;

var sandbox;

describe('domain routes', function() {
  beforeEach(function() {
    req.params.domainId = 'dummy';
    res.locals.currentDomain = req.params.domainId;

    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('getPolicyRow', function() {
    it('should test success case', function() {
      var renderExpectation = sandbox.mock(res).expects('render');

      var fetchExpectation = sandbox.mock(req.restClient).expects('getPolicy');
      fetchExpectation.callsArgWith(1, null, {name: 'name', id: 1, assertions: [{id: 1}]});

      policyHandler.getPolicyRow(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('policyrow');
      expect(renderArgs[1].policies).to.be.an('array').of.length(1);
      expect(renderArgs[1].policies[0]).to.contain({
        name: 'name',
        id: 1,
        fullName: 'name'
      });
    });
  });

  it('should test addPolicy', function() {
    req.body = {
      name: 'name',
      resource: 'res',
      effect: 'effect',
      action: 'action'
    };

    var renderExpectation = sandbox.mock(res).expects('render');

    var putExpectation = sandbox.mock(req.restClient).expects('putPolicy');
    putExpectation.callsArgWith(1, null, {});

    policyHandler.addPolicy(req, res);

    var renderArgs = renderExpectation.args[0];

    expect(renderArgs[0]).to.equal('policyrow');
    expect(renderArgs[1].policies).to.be.an('array').of.length(1);
    expect(renderArgs[1].policies[0]).to.contain({
      name: 'name',
      fullName: 'dummy:policy.name'
    });
  });

  it('should test deletePolicy', function() {
    var restMock = sandbox.mock(req.restClient);
    restMock.expects('deletePolicy').callsArgWith(1, null, {})
        .withArgs({domainName: 'd', policyName: 'p'});

    req.params = {domainId: 'd', policy: 'p'};

    var resMock = sandbox.mock(res);
    resMock.expects('status').withArgs(200).returns(res);
    resMock.expects('json').withArgs({});

    policyHandler.deletePolicy(req, res);

    restMock.verify();
    resMock.verify();
  });

  it('should test deleteAssertion', function() {
    var restMock = sandbox.mock(req.restClient);
    restMock.expects('deleteAssertion').callsArgWith(1, null, {})
        .withArgs({domainName: 'd', policyName: 'p', assertionId: 1});

    req.params = {domainId: 'd', policy: 'p', id: 1};

    var resMock = sandbox.mock(res);
    resMock.expects('status').withArgs(200).returns(res);
    resMock.expects('json').withArgs({});

    policyHandler.deleteAssertion(req, res);

    restMock.verify();
    resMock.verify();
  });

  it('should test addAssertion', function() {
    var restMock = sandbox.mock(req.restClient);
    restMock.expects('putAssertion').callsArgWith(1, null, {})
        .withArgs({domainName: 'd', policyName: 'p', assertion: {
          action: 'a', role: 'd:role.r', resource: 'res:r', effect: 'e'}});

    req.params = {domainId: 'd', policy: 'p', id: 1};

    var resMock = sandbox.mock(res);
    resMock.expects('render').withArgs('partials/assertionrow');

    req.body = {role: 'r', resource: 'res:r', effect: 'e', action: 'a'};

    policyHandler.addAssertion(req, res);

    restMock.verify();
    resMock.verify();
  });
});
