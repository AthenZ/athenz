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

var rolesHandler = require('../../../src/api/roles');
var sinon = require('sinon');
var expect = require('chai').expect;
var restClient = require('../../config/helpers').restClient;
var config = require('../../../config/config.js')();

var sandbox;

describe('roles', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test fetch roles', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getRoles');
    fetchExpectation.callsArgWith(1, null, {list: ['a']});
    var cb = sandbox.spy();

    rolesHandler.fetchRoles({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.be.null;
    expect(cbArgs[1]).to.deep.equal(['a']);
  });

  it('should test fetch roles error', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getRoles');
    fetchExpectation.callsArgWith(1, 'err');
    var cb = sandbox.spy();

    rolesHandler.fetchRoles({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.not.be.null;
    expect(cbArgs[1]).to.be.undefined;
  });

  it('should test fetch role', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getRole');
    fetchExpectation.callsArgWith(1, null, {members: [config.userDomain + '.abc', config.userDomain + '.def', config.userDomain + '.ghi']});
    var cb = sandbox.spy();

    rolesHandler.fetchRole({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.be.null;
    expect(cbArgs[1]).to.deep.equal(['abc', 'def', 'ghi']);
  });

  it('should test fetch role when no members are returned', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getRole');
    fetchExpectation.callsArgWith(1, null, {members: []});
    var cb = sandbox.spy();

    rolesHandler.fetchRole({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.be.null;
    expect(cbArgs[1]).to.deep.equal([]);
  });

  it('should test fetch role error', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getRole');
    fetchExpectation.callsArgWith(1, 'err');
    var cb = sandbox.spy();

    rolesHandler.fetchRole({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.not.be.null;
    expect(cbArgs[1]).to.deep.equal([]);
  });

  describe('addMember to roles', function() {
    it('should test success case', function() {
      var restMock = sandbox.mock(restClient);
      restMock.expects('putMembership')
          .withArgs({domainName: 'd', roleName: 'a', memberName: 'me', auditRef: '',
                    membership: {memberName: 'me'}})
          .callsArgWith(1, null);
      restMock.expects('putMembership')
          .withArgs({domainName: 'd', roleName: 'b', memberName: 'me', auditRef: '',
                    membership: {memberName: 'me'}})
          .callsArgWith(1, {message: 'err'});

      var cb = sandbox.spy();

      rolesHandler.addMember({
        domain: 'd',
        roles: ['a', 'b'],
        member: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];

      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({a: {error: false, msg: ''}, b: {error: true, msg: 'err'}});
      restMock.verify();
    });

    it('should test invalid param case', function() {
      var restMock = sandbox.mock(restClient);
      restMock.expects('putMembership').never();

      var cb = sandbox.spy();

      rolesHandler.addMember({
        domain: 'd',
        roles: null,
        member: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];

      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('Roles is not an array');
      restMock.verify();
    });
  });

  describe('deleteMember to roles', function() {
    it('should test success case', function() {
      var restMock = sandbox.mock(restClient);
      restMock.expects('deleteMembership')
          .withArgs({domainName: 'd', roleName: 'a', memberName: 'me', auditRef: ''})
          .callsArgWith(1, null);
      restMock.expects('deleteMembership')
          .withArgs({domainName: 'd', roleName: 'b', memberName: 'me', auditRef: ''})
          .callsArgWith(1, {message: 'err'});

      var cb = sandbox.spy();

      rolesHandler.deleteMember({
        domain: 'd',
        roles: ['a', 'b'],
        member: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];

      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.be.null;
      expect(cbArgs[1]).to.deep.equal({a: {error: false, msg: ''}, b: {error: true, msg: 'err'}});
      restMock.verify();
    });

    it('should test invalid param case', function() {
      var restMock = sandbox.mock(restClient);
      restMock.expects('deleteMembership').never();

      var cb = sandbox.spy();

      rolesHandler.deleteMember({
        domain: 'd',
        roles: null,
        member: 'me'
      }, restClient, cb);

      var cbArgs = cb.args[0];

      expect(cb.calledOnce).to.be.true;
      expect(cbArgs[0]).to.equal('Roles is not an array');
      restMock.verify();
    });
  });
});
