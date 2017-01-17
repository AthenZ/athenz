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

var roleHandler = require('../../../src/routeHandlers/role');

var sinon = require('sinon');
var expect = require('chai').expect;

var req = require('../../config/helpers').req;
var res = require('../../config/helpers').res;

var sandbox;

describe('role routes', function() {
  beforeEach(function() {
    req.params.domainId = 'dummy';
    res.locals.currentDomain = req.params.domainId;

    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('addRole route', function() {
    it('should test success case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putRole').callsArgWith(1, null, {})
          .withArgs({domainName: 'd', roleName: 'r', role: {name: 'd:role.r', members: ['a'], trust: undefined}});

      var renderExpectation = sandbox.mock(res).expects('render');

      req.params = {domainId: 'd'};
      req.body = {members: 'a', name: 'r'};
      roleHandler.addRole(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('rolerow');
      expect(renderArgs[1].layout).to.equal(false);
      restMock.verify();
    });

    it('should test case when no members', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putRole').callsArgWith(1, 'err', {})
        .withArgs({domainName: 'd', roleName: 'r', role: {name: 'd:role.r', members: [], trust: undefined}});

      var resMock = sandbox.mock(res);
      resMock.expects('render').never();
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('send').withArgs('err');

      req.params = {domainId: 'd'};
      req.body = {name: 'r'};
      roleHandler.addRole(req, res);

      restMock.verify();
      resMock.verify();
    });

    it('should test error case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putRole').callsArgWith(1, 'err', {});

      var resMock = sandbox.mock(res);
      resMock.expects('render').never();
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('send').withArgs('err');

      req.params = {domainId: 'd'};
      req.body = {members: 'a', name: 'r'};
      roleHandler.addRole(req, res);

      restMock.verify();
      resMock.verify();
    });
  });

  describe('deleteRole', function() {
    it('should test success case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('deleteRole').callsArgWith(1, null, {})
          .withArgs({domainName: 'd', roleName: 'r'});


      req.params = {domainId: 'd', role: 'r'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      roleHandler.deleteRole(req, res);

      restMock.verify();
      resMock.verify();
    });

    it('should test error case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('deleteRole').callsArgWith(1, 'err', {});

      var resMock = sandbox.mock(res);
      resMock.expects('render').never();
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('json').withArgs({});

      req.params = {domainId: 'd'};
      roleHandler.deleteRole(req, res);

      restMock.verify();
      resMock.verify();
    });
  });

  describe('getRoleRow', function() {
    it('should handle success case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getRole').callsArgWith(1, null, {name: 'r'});

      var resMock = sandbox.mock(res);
      resMock.expects('render').withArgs('rolerow');

      req.params = {domainId: 'd', role: 'r'};
      roleHandler.getRoleRow(req, res);

      restMock.verify();
      resMock.verify();
    });

    it('should handle error case', function() {
      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getRole').callsArgWith(1, 'err', {});

      var resMock = sandbox.mock(res);
      resMock.expects('render').never();
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('send').withArgs('err');

      req.params = {domainId: 'd', role: 'r'};
      roleHandler.getRoleRow(req, res);

      restMock.verify();
      resMock.verify();
    });
  });
});
