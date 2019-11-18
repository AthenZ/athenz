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

var reqUtils = require('../../../src/utils/req');
var config = require('../../../config/config.js')();

var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox,
  req;

describe('req utils', function() {
  beforeEach(function() {
    req = {
      params: {domainId: 'did'},
      restClient: {},
      query: {},
      body: {}
    };
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test populateErrorData with generic error message', function() {
    var viewData = {type: 'role'};

    req.query.failed = 'yes';
    reqUtils.populateErrorData(viewData, req);
    expect(viewData.message).to.equal('Error - Failed to create role');
  });

  it('should test populateErrorData with specific error message', function() {
    var viewData = {type: 'role'};

    req.query.failed = 'i failed master';
    reqUtils.populateErrorData(viewData, req);
    expect(viewData.message).to.equal('Error - i failed master');
  });

  it('should test populateAppContextErrorMessage when err.message', function() {
    var holder = {};
    var err = {message: 'i failed master'};

    reqUtils.populateAppContextErrorMessage(holder, err);
    expect(holder.appContextMessageType).to.equal('error');
    expect(holder.appContextMessage).to.equal(err.message);
  });

  it('should test populateAppContextErrorMessage when err.message.message', function() {
    var holder = {};
    var err = {message: {message: 'i failed master'}};

    reqUtils.populateAppContextErrorMessage(holder, err);
    expect(holder.appContextMessageType).to.equal('error');
    expect(holder.appContextMessage).to.equal(err.message.message);
  });

  it('should test populateAppContextErrorMessage with no err.message', function() {
    var holder = {};
    var err = {};

    reqUtils.populateAppContextErrorMessage(holder, err);
    expect(holder.appContextMessageType).to.be.undefined;
    expect(holder.appContextMessage).to.be.undefined;
  });

  it('should test checkErr when true', function() {
    var errMsg = 'i failed master';

    var err = {message: 'i failed master'};
    expect(reqUtils.checkErr(errMsg, err)).to.be.true;

    err = {message: {message: 'i failed master'}};
    expect(reqUtils.checkErr(errMsg, err)).to.be.true;
  });

  it('should test checkErr when false', function() {
    var errMsg = 'asdf';

    var err = {message: 'i failed master'};
    expect(reqUtils.checkErr(errMsg, err)).to.be.false;

    err = {message: {message: 'i failed master'}};
    expect(reqUtils.checkErr(errMsg, err)).to.be.false;
  });

  it('should test populateErrorMessage when err.message', function() {
    var toUrl = 'http://blah';

    var err = {message: 'i failed master'};
    expect(reqUtils.populateErrorMessage(toUrl, err)).to.equal('http://blah/?failed=i%20failed%20master');

    err = {message: {message: 'i failed master'}};
    expect(reqUtils.populateErrorMessage(toUrl, err)).to.equal('http://blah/?failed=i%20failed%20master');
  });

  it('should test populateErrorMessage when no err.message', function() {
    var toUrl = 'http://blah';

    var err = {};
    expect(reqUtils.populateErrorMessage(toUrl, err)).to.equal('http://blah/?failed=Operation%20failed.%20Please%20contact%20application%20admin%20if%20this%20issue%20persists.');
  });

  it('should test ascertainDomainType for userdomain', function() {
    var type = reqUtils.ascertainDomainType(config.userDomain + '.beezlebub');
    expect(type).to.deep.equal({domainType: 'userdomain', name: 'beezlebub'});
  });

  it('should test ascertainDomainType for subdomain', function() {
    var type = reqUtils.ascertainDomainType(config.userDomain + '.beezlebub.oog');
    expect(type).to.deep.equal({domainType: 'subdomain', name: 'oog', parent: config.userDomain + '.beezlebub'});
  });

  it('should test ascertainDomainType for domain', function() {
    var type = reqUtils.ascertainDomainType('rummykub');
    expect(type).to.deep.equal({domainType: 'domain', name: 'rummykub'});
  });

  it('should test ascertainDomainType when null', function() {
    var type = reqUtils.ascertainDomainType();
    expect(type).to.equal.null;
  });

  it('should test getDomainDisplayLabel', function() {
    expect(reqUtils.getDomainDisplayLabel('userdomain')).to.equal('Personal');
    expect(reqUtils.getDomainDisplayLabel('subdomain')).to.equal('Sub domain');
    expect(reqUtils.getDomainDisplayLabel('domain')).to.equal('Top level');
    expect(reqUtils.getDomainDisplayLabel('blah')).to.equal('None');
  });

  it('should test getAdminLinks when there is one admin', function() {
    var adminLinkStr = reqUtils.getAdminLinks('rummykub');
	expect(adminLinkStr).to.contain('rummykub');
  });


  it('should test getAdminLinks when there is more than one admin, some with user prefixes', function() {
    var adminLinkStr = reqUtils.getAdminLinks('rummykub,beezlebub,abercadaber');
	expect(adminLinkStr).to.contain('rummykub, beezlebub, abercadaber');
  });

  it('should test getAdminLinks when there are none', function() {
    var adminLinkStr = reqUtils.getAdminLinks('');
    expect(adminLinkStr).to.deep.equal([]);
  });
  it('should test y64Encode for sample string -- asdf', function() {
    expect(reqUtils.y64Encode('asdf')).to.equal('YXNkZg--');
  });
  it('should test y64Decode for sample string -- YXNkZg--', function() {
    expect(reqUtils.y64Decode('YXNkZg--')).to.equal('asdf');
  });
});
