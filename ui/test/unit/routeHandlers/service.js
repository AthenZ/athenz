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

var serviceHandler = require('../../../src/routeHandlers/service');

var sinon = require('sinon');
var expect = require('chai').expect;

var req = require('../../config/helpers').req;
var res = require('../../config/helpers').res;

var sandbox,
  req,
  res;

describe('service routes', function() {
  beforeEach(function() {
    req.params.domainId = 'dummy';
    res.locals.currentDomain = req.params.domainId;

    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('getServiceRow route', function() {
    it('should test success case', function() {
      req.params.service = 'service';

      var renderExpectation = sandbox.mock(res).expects('render');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getServiceIdentity').callsArgWith(1, null, {
        publicKeys: [
          {
            key: 'key',
            id: 'keyid'
          }
        ],
        modified: 'date',
        name: 'dummy.service'
      });

      serviceHandler.getServiceRow(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('partials/servicerow');
      expect(renderArgs[1].domainId).to.equal('dummy');
      expect(renderArgs[1].name).to.equal('service');
      expect(renderArgs[1].fullName).to.equal('dummy.service');
    });
  });

  describe('addService route', function() {
    it('should test success case', function() {
      req.body = {
        name: 'newservice',
        hosts: 'host1,host2',
        keyId: '0',
        key: 'asdf'
      };

      var renderExpectation = sandbox.mock(res).expects('render');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putServiceIdentity').callsArgWith(1, null);

      serviceHandler.addService(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('partials/servicerow');
      expect(renderArgs[1].domainId).to.equal('dummy');
      expect(renderArgs[1].name).to.equal('newservice');
      expect(renderArgs[1].fullName).to.equal('dummy.newservice');
    });

    it('should test success case with no hosts', function() {
      req.body = {
        name: 'newservice',
        keyId: '0',
        key: 'asdf'
      };

      var renderExpectation = sandbox.mock(res).expects('render');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putServiceIdentity').callsArgWith(1, null);

      serviceHandler.addService(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('partials/servicerow');
      expect(renderArgs[1].domainId).to.equal('dummy');
      expect(renderArgs[1].name).to.equal('newservice');
      expect(renderArgs[1].fullName).to.equal('dummy.newservice');
    });
  });

  describe('deleteService', function() {
    it('should test success case', function() {
      req.params.service = 'service';

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('deleteServiceIdentity').callsArgWith(1, null, {})
        .withArgs({domain: 'dummy', service: 'service'});

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      serviceHandler.deleteService(req, res);

      restMock.verify();
      resMock.verify();
    });
  });

  describe('deleteKey', function() {
    it('should test success case', function() {
      req.params.service = 'service';
      req.params.id = 'keyid';

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('deletePublicKeyEntry').callsArgWith(1, null, {})
        .withArgs({domain: 'dummy', service: 'service', id: 'keyid'});

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      serviceHandler.deleteKey(req, res);

      restMock.verify();
      resMock.verify();
    });
  });

  describe('addKey', function() {
    it('should test success case', function() {
      req.params.service = 'newservice';
      req.body = {
        id: 'keyId',
        key: 'key'
      };

      var renderExpectation = sandbox.mock(res).expects('render');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('putPublicKeyEntry').callsArgWith(1, null);

      serviceHandler.addKey(req, res);

      var renderArgs = renderExpectation.args[0];
      expect(renderArgs[0]).to.equal('partials/servicekeyrow');
      restMock.verify();
    });
  });
});
