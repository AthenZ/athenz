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

var routeHandlers = require('../../../src/routeHandlers/main');
var domainRoutes = require('../../../src/routeHandlers/domain');
var commonAPI = require('../../../src/api/common');
var domainHandler = require('../../../src/api/domain');

var req = require('../../config/helpers').req;
var res = require('../../config/helpers').res;

var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox;

describe('main routeHandlers', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test / route', function() {
    var mockResponse = sandbox.mock(res);
    mockResponse.expects('redirect').withArgs('/athenz');

    routeHandlers.redirect(req, res);

    mockResponse.verify();
  });

  it('should test home route', function() {
    res.locals.domains = ['dummy'];
    var mockResponse = sandbox.mock(res);
    mockResponse.expects('redirect').withArgs('/athenz/domain/dummy/roles');

    routeHandlers.home(req, res);

    sandbox.mock(res).expects('render').withArgs('home', {});
  });

  it('should test notFound route for non ajax context', function() {
    req.originalUrl = 'dummy';
    req.method = 'GET';

    var mock = sandbox.mock(res);
    mock.expects('render').withArgs('404', {
      pageTitle: '404 Not Found',
      url: 'dummy'
    });

    routeHandlers.notFound(req, res);
     
    mock.verify();
  });

  it('should test notFound route for ajax context', function() {
    req.originalUrl = 'ajax';

    var mock = sandbox.mock(res);
    mock.expects('status').withArgs(404).returns(res);
    mock.expects('send').withArgs('');

    routeHandlers.notFound(req, res);

    mock.verify();
  });

  describe('init', function() {
    var mockCommon;

    beforeEach(function() {
      req.restClient.getDomainList = function() {};
      mockCommon = sandbox.mock(commonAPI);
    });

    it('should populate static data', function() {
      req.username = 'you';
      routeHandlers.init(req, res, function() {});

      expect(res.locals.navApps).to.be.an('array').of.length(1);
      mockCommon.verify();
    });

    it('should not populate common data if api', function() {
      req.originalUrl = 'http://athenz.yahoo.com/api';
      mockCommon.expects('getPageCommonData').never();

      routeHandlers.init(req, res, function() {});

      mockCommon.verify();
    });

    it('should test fetchUserDomains', function() {
      req.params.domainId = 'dummy';
      var fetchExpectation = sandbox.mock(domainHandler).expects('fetchUserDomains');
      fetchExpectation.callsArgWith(2, null, [{name: 'dummy', type: 'Top level', admin: true}]);

      var cb = sandbox.spy();

      routeHandlers.init(req, res, cb);
      expect(cb.calledOnce).to.be.true;

      expect(res.locals.domains).to.deep.equal([{name: 'dummy', type: 'Top level', admin: true, active: 'active'}]);
    });

    it('should test fetchUserDomains with no domains', function() {
      var fetchExpectation = sandbox.mock(domainHandler).expects('fetchUserDomains');
      fetchExpectation.callsArgWith(2, null, []);

      var cb = sandbox.spy();

      routeHandlers.init(req, res, cb);
      expect(cb.calledOnce).to.be.true;

      expect(res.locals.domains).to.deep.equal([]);
      expect(res.locals.noDomains).to.equal('You do not have any domains that you belong to or are an admin of.');
    });

    it('should test fetchUserDomains with data not an array', function() {
      var fetchExpectation = sandbox.mock(domainHandler).expects('fetchUserDomains');
      fetchExpectation.callsArgWith(2, null, {});

      var cb = sandbox.spy();

      routeHandlers.init(req, res, cb);
      expect(cb.calledOnce).to.be.true;

      expect(res.locals.domains).to.deep.equal([]);
      expect(res.locals.noDomains).to.equal('You do not have any domains that you belong to or are an admin of.');
    });

    it('should test fetchUserDomains when err', function() {
      var fetchExpectation = sandbox.mock(domainHandler).expects('fetchUserDomains');
      fetchExpectation.callsArgWith(2, {message: 'error msg'});

      var cb = sandbox.spy();

      routeHandlers.init(req, res, cb);
      expect(cb.calledOnce).to.be.true;

      expect(res.locals.domains).to.deep.equal([]);
      expect(res.locals.appContextMessageType).to.equal('error');
      expect(res.locals.appContextMessage).to.equal('error msg');
    });
  });

  describe('domain routes', function() {
    var mock;

    beforeEach(function() {
      mock = sandbox.mock(domainRoutes);
      mock.expects('domainDetails').callsArgWith(2);
    });

    it('should test domain roles route', function() {
      mock.expects('roleRoute').once();

      req.params.section = 'role';
      req.params.domainId = 'dummy';
      routeHandlers.domainRoutes(req, res);

      mock.verify();
    });

    it('should test domain service route', function() {
      mock = sandbox.mock(domainRoutes);
      mock.expects('serviceRoute').once();

      req.params.section = 'service';
      req.params.domainId = 'dummy';
      routeHandlers.domainRoutes(req, res);

      mock.verify();
    });

    it('should test domain policy route', function() {
      mock = sandbox.mock(domainRoutes);
      mock.expects('policyRoute').once();

      req.params.section = 'policy';
      req.params.domainId = 'dummy';
      routeHandlers.domainRoutes(req, res);

      mock.verify();
    });

    it('should throw error on invalid domain section', function() {
      req.params.section = 'invalid';
      req.params.domainId = 'dummy';

      mock = sandbox.mock(res);
      mock.expects('render').once().withArgs('404');

      routeHandlers.domainRoutes(req, res);
      mock.verify();
    });
  });

  describe('manage domains', function() {
    it('should test manage domain ok', function() {
		var cliMock = sandbox.mock(req.restClient);
		cliMock.expects('getDomain').callsArgWith(1, null, {}).once();

		res.locals.domains = [
			{name: 'test.domain'}
		];
		var mockResponse = sandbox.mock(res);
		mockResponse.expects('render').withArgs('managedomains', 
			{
				manageDomainActive: "active",
				pageTitle: "Manage Domains",
				section: { id: "Manage My Domains" }
			});

      routeHandlers.manageDomains(req, res);
	  cliMock.verify();
      mockResponse.verify();
    });

    it('should test manage domain bad', function() {
		var cliMock = sandbox.mock(req.restClient);
		cliMock.expects('getDomain').callsArgWith(1, 'err', {}).once();

		res.locals.domains = [
			{name: 'test.domain'}
		];
		var mockResponse = sandbox.mock(res);
		mockResponse.expects('render').withArgs('managedomains', 
			{
				manageDomainActive: "active",
				pageTitle: "Manage Domains",
				section: { id: "Manage My Domains" }
			});

      routeHandlers.manageDomains(req, res);
	  cliMock.verify();
      mockResponse.verify();
    });
  });

});
