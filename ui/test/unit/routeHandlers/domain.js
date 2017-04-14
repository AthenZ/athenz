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

var routeHandlers = require('../../../src/routeHandlers/domain');
var domainHandler = require('../../../src/api/domain');
var rolesHandler = require('../../../src/api/roles');
var servicesHandler = require('../../../src/api/services');
var policiesHandler = require('../../../src/api/policies');
var config = require('../../../config/config.js')();

var req = require('../../config/helpers').req;
var res = require('../../config/helpers').res;

var sinon = require('sinon');
var expect = require('chai').expect;

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

  describe('handleAddDomainError', function() {
    var domainData,
      err,
      toUrl;

    beforeEach(function() {
      domainData = {
        adminUsers: config.userDomain + '.falafel',
        name: 'kabob',
        parent: 'babaganoush'
      },
      toUrl = '/athenz/domain/';
    });

    it('should test when: Entry already exists', function() {
      req.params.domainType = 'domain';
      var responseExpectation = sandbox.mock(res).expects('redirect');
      err = {
        message: 'Entry already exists'
      };
      routeHandlers.handleAddDomainError(req, res, domainData, toUrl, err);

      var responseArgs = responseExpectation.args[0];
      expect(responseArgs[0]).to.equal(303);
      expect(responseArgs[1]).to.equal('/athenz/domain/babaganoush.kabob/role?failed=Top%20level%20domain%20babaganoush.kabob%20already%20exists');
    });

    it('should test when: Forbidden and domainType subdomain', function() {
      req.params.domainType = 'subdomain';
      var responseExpectation = sandbox.mock(res).expects('redirect');
      err = {
        message: 'Forbidden'
      };

      var rolesExpectation = sandbox.mock(rolesHandler).expects('fetchRole');
      rolesExpectation.callsArgWith(2, null, ['mem1', 'mem2', 'mem3', 'mem4']);

      routeHandlers.handleAddDomainError(req, res, domainData, toUrl, err);

      var responseArgs = responseExpectation.args[0];
      expect(responseArgs[0]).to.equal(303);
      expect(responseArgs[1]).to.equal('/athenz/domain/?admins=mem1%2Cmem2%2Cmem3%2Cmem4');
    });

    it('should test when: Forbidden, domainType domain, and admins', function() {
      req.params.domainType = 'domain';
      var responseExpectation = sandbox.mock(res).expects('redirect');
      err = {
        message: 'Forbidden',
        admins: ['mem1', 'mem2', 'mem3', 'mem4']
      };

      routeHandlers.handleAddDomainError(req, res, domainData, toUrl, err);

      var responseArgs = responseExpectation.args[0];
      expect(responseArgs[0]).to.equal(303);
      expect(responseArgs[1]).to.equal('/athenz/domain/?admins=mem1%2Cmem2%2Cmem3%2Cmem4');
    });

    it('should test when: Forbidden, domainType domain, and no admins', function() {
      req.params.domainType = 'domain';
      var responseExpectation = sandbox.mock(res).expects('redirect');
      err = {
        message: 'Forbidden'
      };

      routeHandlers.handleAddDomainError(req, res, domainData, toUrl, err);

      var responseArgs = responseExpectation.args[0];
      expect(responseArgs[0]).to.equal(303);
      expect(responseArgs[1]).to.equal('/athenz/domain/?failed=Credential%20error.%20Please%20report%20issue%20to%20athenz-ui%20admin.%20Thank%20you.');
    });

    it('should test for all other generic errors', function() {
      req.params.domainType = 'domain';
      var responseExpectation = sandbox.mock(res).expects('redirect');
      err = {
        message: 'Somthin happened'
      };

      routeHandlers.handleAddDomainError(req, res, domainData, toUrl, err);

      var responseArgs = responseExpectation.args[0];
      expect(responseArgs[0]).to.equal(303);
      expect(responseArgs[1]).to.equal('/athenz/domain/?failed=Somthin%20happened');
    });
  });

  it('should test domainDetails route', function() {
    var fetchExpectation = sandbox.mock(domainHandler).expects('fetchDomainMetadata');
    fetchExpectation.callsArgWith(2, null, {names: ['name']});

    var cb = sandbox.spy();

    routeHandlers.domainDetails(req, res, cb);

    expect(res.locals.domainDetails).to.deep.equal({names: ['name']});
    expect(cb.calledOnce).to.be.true;
  });

  it('should test domainDetails route with error', function() {
    var fetchExpectation = sandbox.mock(domainHandler).expects('fetchDomainMetadata');
    fetchExpectation.callsArgWith(2, 'err');

    var cb = sandbox.spy();

    routeHandlers.domainDetails(req, res, cb);

    expect(res.locals.domainDetails).to.deep.equal({});
    expect(cb.calledOnce).to.be.true;
  });

  describe('roles route', function() {
    it('should test all success case', function() {
      var fetchExpectation = sandbox.mock(rolesHandler).expects('fetchRoles');
      fetchExpectation.callsArgWith(2, null, [{name: 'role.name'}]);

      var renderExpectation = sandbox.mock(res).expects('render');

      req.params.section = 'roles';
      routeHandlers.roleRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].roles).to.deep.equal([{
        name: 'name',
        fullName: 'role.name',
        domainId: 'dummy',
        type: 'Regular',
        deleteUrl: '/athenz/domain/dummy/role/name/delete',
        members: []
      }]);
      expect(fetchArgs[0].domainId).to.equal('dummy');
    });

    it('should test roles route with fetchRoles error', function() {
      var fetchExpectation = sandbox.mock(rolesHandler).expects('fetchRoles');
      fetchExpectation.callsArgWith(2, true);
      var renderExpectation = sandbox.mock(res).expects('render');

      req.params.section = 'roles';
      routeHandlers.roleRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].items).to.be.undefined;
      expect(renderArgs[1].totalCount).to.be.undefined;
      expect(fetchArgs[0].domainId).to.equal('dummy');
    });
  });

  describe('services route', function() {
    it('should test all success case', function() {
      var fetchExpectation = sandbox.mock(servicesHandler).expects('fetchServices');
      fetchExpectation.callsArgWith(2, null, [{modified: 'modified', name: 'name'}]);

      var renderExpectation = sandbox.mock(res).expects('render');

      req.params.section = 'services';
      routeHandlers.serviceRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].services).to.deep.equal([
        {
          'addKeyUrl': '/athenz/domain/dummy/service/name/key/add',
          'deleteUrl': '/athenz/domain/dummy/service/name/delete',
          'domainId': 'dummy',
          'fullName': 'name',
          'modified': 'modified',
          'name': 'name',
          'user': null
        }
      ]);
      expect(fetchArgs[0].domainId).to.equal('dummy');
    });

    it('should test getServiceIdentity error case', function() {
      var fetchExpectation = sandbox.mock(servicesHandler).expects('fetchServices');
      fetchExpectation.callsArgWith(2, {err: 'error'});

      var renderExpectation = sandbox.mock(res).expects('render');

      req.params.section = 'services';
      routeHandlers.serviceRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1]).to.deep.equal({
        pageTitle: 'Home : Services',
        itemURI: '/athenz/domain/dummy/service/',
        addService: '/athenz/domain/dummy/service/add'
      });
      expect(renderArgs[1].services).to.be.undefined;
      expect(fetchArgs[0].domainId).to.equal('dummy');
    });

    it('should test services route with error', function() {
      var fetchExpectation = sandbox.mock(servicesHandler).expects('fetchServices');
      fetchExpectation.callsArgWith(2, true);
      var renderExpectation = sandbox.mock(res).expects('render');

      req.params.section = 'services';
      routeHandlers.serviceRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].items).to.be.undefined;
      expect(renderArgs[1].totalCount).to.be.undefined;
      expect(fetchArgs[0].domainId).to.equal('dummy');
      expect(fetchArgs[0].page).to.be.undefined;
    });
  });

  describe('policies route', function() {
    it('should test all success case', function() {
      var fetchExpectation = sandbox.mock(policiesHandler).expects('fetchPolicies');
      fetchExpectation.callsArgWith(2, null, [{name: 'name'}]);

      var renderExpectation = sandbox.mock(res).expects('render');

      var fetchRolesExpectation = sandbox.mock(rolesHandler).expects('fetchRoles');
      fetchRolesExpectation.callsArgWith(2, null, [{name: 'name', id: 1}]);

      req.params.section = 'policies';
      routeHandlers.policyRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].policies).to.deep.equal([{
        name: 'name',
        addAssertion: '/athenz/domain/dummy/policy/name/assertion/add',
        domainId: 'dummy',
        fullName: 'name',
        deleteUrl: '/athenz/domain/dummy/policy/name/delete'
      }]);
      expect(renderArgs[1].roles).to.deep.equal(['name']);
      expect(fetchArgs[0].domainId).to.equal('dummy');
      expect(fetchArgs[0].page).to.be.undefined;
    });

    it('should test roles policies with error', function() {
      var fetchExpectation = sandbox.mock(policiesHandler).expects('fetchPolicies');
      fetchExpectation.callsArgWith(2, true);
      var renderExpectation = sandbox.mock(res).expects('render');

      var fetchRolesExpectation = sandbox.mock(rolesHandler).expects('fetchRoles');
      fetchRolesExpectation.callsArgWith(2, 'err');


      req.params.section = 'policies';
      routeHandlers.policyRoute(req, res);

      var renderArgs = renderExpectation.args[0];
      var fetchArgs = fetchExpectation.args[0];
      expect(renderArgs[0]).to.equal('domain');
      expect(renderArgs[1].policies).to.be.undefined;
      expect(renderArgs[1].roles).to.be.undefined;
      expect(fetchArgs[0].domainId).to.equal('dummy');
      expect(fetchArgs[0].page).to.be.undefined;
    });
  });

  describe('should test addDomainsPage', function() {
    it('should test add top level domain', function() {
      req.params = {domainType: 'domain'};
      var renderExpectation = sandbox.mock(res).expects('render');

      routeHandlers.addDomainsPage(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('adddomains');
      expect(renderArgs[1].domainTypes.domain.active).to.equal('active');
    });

    it('should test add sublevel domain', function() {
      req.params = {domainType: 'subdomain'};

      var renderExpectation = sandbox.mock(res).expects('render');
      routeHandlers.addDomainsPage(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('adddomains');
      expect(renderArgs[1].domainTypes.subdomain.active).to.equal('active');
    });

    it('should test add user domain when user domain does not exist', function() {
      req.params = {domainType: 'userdomain'};

      var renderExpectation = sandbox.mock(res).expects('render');

      var domainMock = sandbox.mock(domainHandler);
      domainMock.expects('fetchDomainMetadata').callsArgWith(2, 'err');

      routeHandlers.addDomainsPage(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal('adddomains');
      expect(renderArgs[1].domainTypes.userdomain.active).to.equal('active');
    });

    it('should test add user domain when user domain exist', function() {
      req.params = {domainType: 'userdomain'};

      var renderExpectation = sandbox.mock(res).expects('redirect');

      var domainMock = sandbox.mock(domainHandler);
      domainMock.expects('fetchDomainMetadata').callsArgWith(2, null, {name: 'user'});

      routeHandlers.addDomainsPage(req, res);

      var renderArgs = renderExpectation.args[0];

      expect(renderArgs[0]).to.equal(303);
      expect(renderArgs[1]).to.contain('already%20exists');
    });
  });

  describe('deleteMember', function() {
    it('should test delete member', function() {
      req.params = {domainId: 'd', member: 'm'};
      req.body = {roles: 'role'};

      var resMock = sandbox.mock(res);
      resMock.expects('json').withArgs('blah');

      var roleMock = sandbox.mock(rolesHandler);
      roleMock.expects('deleteMember').callsArgWith(2, null, 'blah')
          .withArgs({domain: 'd', roles: ['role'], member: 'm'});

      routeHandlers.deleteMember(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test delete member with alternate source of params', function() {
      req.params = {domainId: 'd'};
      req.body = {member: 'm', roles: ['a', 'b']};

      var resMock = sandbox.mock(res);
      resMock.expects('json').withArgs('blah');

      var roleMock = sandbox.mock(rolesHandler);
      roleMock.expects('deleteMember').callsArgWith(2, null, 'blah')
          .withArgs({domain: 'd', roles: ['a', 'b'], member: 'm'});

      routeHandlers.deleteMember(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test delete member error', function() {
      req.params = {domainId: 'd', member: 'm'};
      req.body = {roles: 'role'};

      var resMock = sandbox.mock(res);
      resMock.expects('json').withArgs([]);
      resMock.expects('status').withArgs(500);

      var roleMock = sandbox.mock(rolesHandler);
      roleMock.expects('deleteMember').callsArgWith(2, 'blah')
          .withArgs({domain: 'd', roles: ['role'], member: 'm'});

      routeHandlers.deleteMember(req, res);

      resMock.verify();
      roleMock.verify();
    });
  });

  describe('postMember', function() {
    it('should test post member', function() {
      req.params = {domainId: 'd'};
      req.body = {roles: 'role', members: 'm'};

      var expectedParams = {domain: 'd', roles: ['role'], member: 'm'};
      var resMock = sandbox.mock(res);
      resMock.expects('json').withArgs({params: expectedParams, roles: 'blah'});

      var roleMock = sandbox.mock(rolesHandler);
      roleMock.expects('addMember').callsArgWith(2, null, 'blah')
          .withArgs(expectedParams);

      routeHandlers.postMember(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test postMember error', function() {
      req.params = {domainId: 'd'};
      req.body = {roles: 'role', members: 'm'};

      var expectedParams = {domain: 'd', roles: ['role'], member: 'm'};

      var resMock = sandbox.mock(res);
      resMock.expects('json').withArgs({params: expectedParams, roles: {}});
      resMock.expects('status').withArgs(500);

      var roleMock = sandbox.mock(rolesHandler);
      roleMock.expects('addMember').callsArgWith(2, 'blah')
          .withArgs({domain: 'd', roles: ['role'], member: 'm'});

      routeHandlers.postMember(req, res);

      resMock.verify();
      roleMock.verify();
    });
  });

  describe('addDomain', function() {

    it('should test add top level domain', function() {
      req.params = {domainType: 'domain'};
      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('addDomain').callsArgWith(2, null, 'blah');

      routeHandlers.addDomain(req, res);
    });

    it('should test add sub domain', function() {
      req.params = {domainType: 'subdomain'};

      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('addSubDomain').callsArgWith(2, null, 'blah');

      routeHandlers.addDomain(req, res);

	  roleMock.verify();
    });

    it('should test add user domain', function() {
      req.params = {domainType: 'userdomain'};

      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('addUserDomain').callsArgWith(2, null, 'blah');

      routeHandlers.addDomain(req, res);

	  roleMock.verify();
    });

	/*	
    it('should test unknown type', function() {
      req.params = {domainType: 'unknown'};

      var roleMock = sandbox.mock(domainHandler);

      routeHandlers.addDomain(req, res);

	  roleMock.verify();
    });
	*/

  });

  describe('deleteDomain', function() {
    it('should test deleteDomain', function() {
      req.params = {domainId: 'me'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('deleteDomain').callsArgWith(2, null, 'blah');

      routeHandlers.deleteDomain(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test deleteSubDomain', function() {
      req.params = {domainId: 'me.1'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('deleteSubDomain').callsArgWith(2, null, 'blah');

      routeHandlers.deleteDomain(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test deleteUserDomain', function() {
      req.params = {domainId: config.userDomain + '.me'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('json').withArgs({});

      var roleMock = sandbox.mock(domainHandler);
      roleMock.expects('deleteUserDomain').callsArgWith(2, null, 'blah');

      routeHandlers.deleteDomain(req, res);

      resMock.verify();
      roleMock.verify();
    });

    it('should test invalid domain deletition', function() {
      req.params = {domainId: ''};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('json').withArgs({});

      routeHandlers.deleteDomain(req, res);

      resMock.verify();
    });
  });
  describe('editDomain', function() {
    it('should test success case', function() {
      req.params = {domainId: config.userDomain + '.me'};
      req.body = {accountid: 'new blah'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('send').withArgs('Success');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getDomain').callsArgWith(1, null, {account: 'blah'});
      restMock.expects('putDomain').callsArgWith(1, null, {account: 'new blah'});

      routeHandlers.editDomain(req, res);

      resMock.verify();
      restMock.verify();
    });

    it('should test fetch domain failure case', function() {
      req.params = {domainId: config.userDomain + '.me'};
      req.body = {accountid: 'new blah'};

      var resMock = sandbox.mock(res);
      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('send').withArgs('Failed to fetch Domain data');

      var restMock = sandbox.mock(req.restClient);
      restMock.expects('getDomain').callsArgWith(1, 'err');
      restMock.expects('putDomain').never();

      routeHandlers.editDomain(req, res);

      resMock.verify();
      restMock.verify();
    });
  });

  describe('allDomains', function() {
    var mock, resMock;

    beforeEach(function() {
      mock = sandbox.mock(domainHandler);
      resMock = sandbox.mock(res);
    });

    afterEach(function() {
      sandbox.restore();
    });

    it('should test allDomains', function() {
      mock.expects('fetchAllDomains').once()
        .callsArgWith(2, null, {});

      resMock.expects('status').withArgs(200).returns(res);
      resMock.expects('send').withArgs('Success');

      routeHandlers.allDomains(req, res);

      mock.verify();
    });

    it('should test allDomains failure', function() {
      mock.expects('fetchAllDomains').once()
        .callsArgWith(2, {message: 'error'});

      resMock.expects('status').withArgs(500).returns(res);
      resMock.expects('send').withArgs('error');

      routeHandlers.allDomains(req, res);

      mock.verify();
    });
  });

});
