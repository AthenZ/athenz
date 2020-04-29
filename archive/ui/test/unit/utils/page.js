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

var pageUtils = require('../../../src/utils/page.js');
var expect = require('chai').expect;

describe('page utils', function() {
  it('should add app context message', function() {
    var req = {query: {editWlError: 'yes'}},
      res = {locals: {}, entityType: 'Role'};

    pageUtils.setAppContextMessage(req, res);
    expect(res.locals.appContextMessageType).to.equal('error');

    req = {query: {createdRole: 'yes'}},
    res = {locals: {}, entityType: 'Role'};

    pageUtils.setAppContextMessage(req, res);
    expect(res.locals.appContextMessageType).to.equal('');

    req = {query: {blah: 'yes'}},
    res = {locals: {}, entityType: 'Role'};

    pageUtils.setAppContextMessage(req, res);
    expect(res.locals.appClassContext).to.be.undefined;
    expect(res.locals.appContextMessageType).to.be.undefined;
  });

  it('should add app context message from failed reason', function() {
    var req = {query: {failed: 'reason'}},
      res = {locals: {}, entityType: 'Role'};

    pageUtils.setAppContextMessage(req, res);
    expect(res.locals.appContextMessage).to.equal('reason');
    expect(res.locals.appContextMessageType).to.equal('error');
  });

  it('should add app context message from success reason', function() {
    var req = {query: {success: 'reason'}},
      res = {locals: {}, entityType: 'Role'};

    pageUtils.setAppContextMessage(req, res);
    expect(res.locals.appContextMessage).to.equal('reason');
    expect(res.locals.appContextMessageType).to.equal('success');
  });

  it('should test isUriSectionOf', function() {
    expect(pageUtils.isUriSectionOf('roles', 'role')).to.be.true;
  });

  it('should test getDomainTypes', function() {
    var data = pageUtils.getDomainTypes({});
    expect(data.domain.active).to.equal('active');

    data = pageUtils.getDomainTypes({domainType: 'subdomain'});
    expect(data.subdomain.active).to.equal('active');
  });

  it('should test cleanupOriginalUrl', function() {
    expect(pageUtils.cleanupOriginalUrl('http://athenz.ui?search=blah')).to.equal('http://athenz.ui/');
    expect(pageUtils.cleanupOriginalUrl('http://athenz.ui?search=blah&service=service&domainid=domainid')).to.equal('http://athenz.ui/?service=service&domainid=domainid');
    expect(pageUtils.cleanupOriginalUrl('http://athenz.ui?search=blah&addError=error&service=service&domainid=domainid&addWgError=error')).to.equal('http://athenz.ui/?service=service&domainid=domainid');
  });

  it('should test getCurrentSection', function() {
    expect(pageUtils.getCurrentSection({roleId: 1})).to.contain({title: 'Role'});
    expect(pageUtils.getCurrentSection({serviceId: 1})).to.contain({title: 'Service'});
    expect(pageUtils.getCurrentSection({policyId: 1})).to.contain({title: 'Policy'});
    expect(pageUtils.getCurrentSection({})).to.deep.contain({});
  });

  it('should test initCommonData', function() {
	  var req = {
		  query: {failed: 'reason'}, 
		  params: {
			  domainId: 'testdomain',
			  section: 'role'
		  },
		  body : {token: 'testtoken'},
		  config: {envLabel: 'testlabel', serviceFQN: 'athenz.console.dev'},
	  },
      res = {locals: {}, entityType: 'Role'};

    pageUtils.initCommonData(req, res);
    expect(res.locals.appContextMessage).to.equal('reason');
    expect(res.locals.appContextMessageType).to.equal('error');
  });

});
