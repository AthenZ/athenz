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

var handler = require('../../../src/api/domain');
var restClient = require('../../config/helpers').restClient;

var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox;

describe('domain api', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('fetchDomainMetadata', function() {
    it('should test domain meta route with get domain success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('getDomain');
      fetchDomainExpectation.callsArgWith(1, null, {
        enabled: true,
        auditEnabled: false,
        account: '149134300625',
        modified: '2016-06-06T22:29:11.095Z',
        name: 'iaas.athenz',
        id: '3f15c000-f86a-11e5-9e9f-51d5b335122d'
      });

      var cb = sandbox.spy();

      handler.fetchDomainMetadata({
        domainId: 'did'
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({
        enabled: true,
        editUrl: '/athenz/domain/iaas.athenz/edit',
        auditEnabled: false,
        account: '149134300625',
        modified: '2016-06-06T22:29:11.095Z',
        name: 'iaas.athenz',
        id: '3f15c000-f86a-11e5-9e9f-51d5b335122d'
      });
    });

    it('should test domain meta route with get domain failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('getDomain');
      fetchDomainExpectation.callsArgWith(1, 'err');

      var cb = sandbox.spy();

      handler.fetchDomainMetadata({
        domainId: 'did'
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('err');
    });
  });

  describe('addDomain', function() {
    it('should test add top level domain with success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postDomain');
      fetchDomainExpectation.callsArgWith(
        1,
        null,
        {modified: '2016-06-30T23:42:01.570Z', name: 'messageboards', id: '3e262420-3f1c-11e6-bb30-33e481a36a9f'}
      );

      var cb = sandbox.spy();

      handler.addDomain({
        name: '',
        adminUsers: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({modified: '2016-06-30T23:42:01.570Z', name: 'messageboards', id: '3e262420-3f1c-11e6-bb30-33e481a36a9f'});
    });

    it('should test add top level domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postDomain');
      fetchDomainExpectation.callsArgWith(1, {status: 401, message: {code: 401, message: 'Invalid credentials'}, error: null});

      var cb = sandbox.spy();

      handler.addDomain({
        name: '',
        adminUsers: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.deep.equal({status: 401, message: {code: 401, message: 'Invalid credentials'}, error: null});
    });

    it('should test add sub domain with success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postSubDomain');
      fetchDomainExpectation.callsArgWith(1, null, {modified: '2016-06-30T23:47:48.579Z', name: 'messageboards.test1', id: '0cfb8330-3f1d-11e6-bb30-33e481a36a9f'});

      var cb = sandbox.spy();

      handler.addSubDomain({
        parent: '',
        name: '',
        adminUsers: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({modified: '2016-06-30T23:47:48.579Z', name: 'messageboards.test1', id: '0cfb8330-3f1d-11e6-bb30-33e481a36a9f'});
    });

    it('should test add sub domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postSubDomain');
      fetchDomainExpectation.callsArgWith(1, {status: 403, message: {code: 403, message: 'Forbidden'}, error: null});

      var cb = sandbox.spy();

      handler.addSubDomain({
        parent: '',
        name: '',
        adminUsers: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.deep.equal({status: 403, message: {code: 403, message: 'Forbidden'}, error: null});
    });

    it('should test add user domain with success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postUserDomain');
      fetchDomainExpectation.callsArgWith(1, null, {modified: '2016-07-01T00:09:53.990Z', name: 'user.manavc', id: '22fd2e60-3f20-11e6-bb30-33e481a36a9f'});

      var cb = sandbox.spy();

      handler.addUserDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({
        'modified': '2016-07-01T00:09:53.990Z',
        'name': 'user.manavc',
        'id': '22fd2e60-3f20-11e6-bb30-33e481a36a9f'
      });
    });

    it('should test add user domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('postUserDomain');
      fetchDomainExpectation.callsArgWith(1, {'status': 400, 'message': {'code': 400, 'message': 'Entry already exists'}, 'error': null});

      var cb = sandbox.spy();

      handler.addUserDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.deep.equal({'status': 400, 'message': {'code': 400, 'message': 'Entry already exists'}, 'error': null});
    });
  });

  describe('deleteDomain', function() {
    //Enable when this is a valid usecase. For sysadmins perhaps?
    /*
    it('should test delete top level domain with success', function () {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteTopLevelDomain');
      fetchDomainExpectation.callsArgWith(1, null, {});

      var cb = sandbox.spy();

      handler.deleteDomain({
       name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({});
    });
    */

    it('should test delete top level domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteTopLevelDomain');
      fetchDomainExpectation.callsArgWith(1, {'status': 403, 'message': {'code': 403, 'message': 'Forbidden'}, 'error': null});

      var cb = sandbox.spy();

      handler.deleteDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.deep.equal({'status': 403, 'message': {'code': 403, 'message': 'Forbidden'}, 'error': null});
    });

    //this is actually true. when the deletion goes through, we get nothing back.
    it('should test delete sub domain with success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteSubDomain');
      fetchDomainExpectation.callsArgWith(1, null, {});

      var cb = sandbox.spy();

      handler.deleteSubDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({});
    });

    it('should test delete sub domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteSubDomain');
      fetchDomainExpectation.callsArgWith(1, {'status': 403, 'message': {'code': 403, 'message': 'Forbidden'}, 'error': null});

      var cb = sandbox.spy();

      handler.deleteSubDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.deep.equal({'status': 403, 'message': {'code': 403, 'message': 'Forbidden'}, 'error': null});
    });

    //this is actually true. when the deletion goes through, we get nothing back.
    it('should test delete user domain with success', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteUserDomain');
      fetchDomainExpectation.callsArgWith(1, null, {});

      var cb = sandbox.spy();

      handler.deleteUserDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({});
    });

    //TODO: fill actual error message
    it('should test delete user domain with failure', function() {
      var fetchDomainExpectation = sandbox.mock(restClient).expects('deleteUserDomain');
      fetchDomainExpectation.callsArgWith(1, 'err');

      var cb = sandbox.spy();

      handler.deleteUserDomain({
        name: ''
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('err');
    });
  });

  describe('test fetchUserDomains', function() {
    it('should test all success case', function() {
      var mockRest = sandbox.mock(restClient);
      mockRest.expects('getDomainList').withArgs({roleMember: 'me'})
      .callsArgWith(1, null, {names: ['x', 'y']});
      mockRest.expects('getDomainList').withArgs({roleMember: 'me', roleName: 'admin'})
      .callsArgWith(1, null, {names: ['y']});

      var cb = sandbox.spy();

      handler.fetchUserDomains({
        userId: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal(null);
      expect(cbArgs[1]).to.deep.equal([{name: 'x', admin: false, type: 'Top level'}, {name: 'y', admin: true, type: 'Top level'}]);
      mockRest.verify();
    });

    it('should test all api error case', function() {
      var mockRest = sandbox.mock(restClient);
      mockRest.expects('getDomainList').withArgs({roleMember: 'me'})
      .callsArgWith(1, 'err');
      mockRest.expects('getDomainList').withArgs({roleMember: 'me', roleName: 'admin'})
      .callsArgWith(1, 'err');

      var cb = sandbox.spy();

      handler.fetchUserDomains({
        userId: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('err');
      mockRest.verify();
    });
  });

  describe('fetchAllDomains', function() {
    it('should test success case', function() {
      var mockRest = sandbox.mock(restClient);
      mockRest.expects('getDomainList').callsArgWith(1, null, {names: ['x']});

      var cb = sandbox.spy();

      handler.fetchAllDomains({}, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal(null);
      expect(cbArgs[1]).to.deep.equal(['x']);
      mockRest.verify();
    });

    it('should test error case', function() {
      var mockRest = sandbox.mock(restClient);
      mockRest.expects('getDomainList').callsArgWith(1, 'err');

      var cb = sandbox.spy();

      handler.fetchAllDomains({}, restClient, cb);

      var cbArgs = cb.args[0];
      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('err');
      mockRest.verify();
    });
  });
});
