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

var viewUtils = require('../../../src/utils/view');

var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox,
  res;

describe('view utils', function() {
  beforeEach(function() {
    res = {render: function() {}};
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should call render if no api calls are pending', function() {
    var mock = sandbox.mock(res);
    mock.expects('render').withArgs('view', 'data').once();

    viewUtils.render(res, 'view', 'data', 0);
    mock.verify();
  });

  it('should not call render if api calls are pending', function() {
    var mock = sinon.mock(res);
    mock.expects('render').withArgs('view', 'data').never();

    viewUtils.render(res, 'view', 'data', 1);
    mock.verify();
  });

  it('should call cb pendingApiCount is 0', function() {
    var cb = sandbox.spy();
    viewUtils.callCb(cb, 'output', 0);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.be.null;
    expect(cbArgs[1]).to.equal('output');
  });

  it('should not call cb pendingApiCount is 0', function() {
    var cb = sandbox.spy();
    viewUtils.callCb(cb, 'output', 1);

    expect(cb.calledOnce).to.be.false;
  });

  it('should highlight current item in list', function() {
    expect(viewUtils.highlightCurrent([{id: 'a'}, {id: 'b'}], 'a'))
        .to.deep.equal([{id: 'a', highlight: 'highlight'}, {id: 'b'}], 'a');
  });

  it('should populateRoleData', function() {
    expect(viewUtils.populateRoleData({
      name: 'role',
      domainId: 'domainId',
      members: ['a', 'user.b'],
      auditLog: [{action: 'ADD', admin: 'user.a', created: '2016-06-28T23:28:29.000Z', member: 'user.b'}]
    }))
      .to.deep.equal({
        'domainId': 'domainId',
        'deleteUrl': '/athenz/domain/domainId/role/role/delete',
        'fullName': 'role',
        'name': 'role',
        'type': 'Regular',
        'members': [{'name': 'a'}, {'name': 'user.b', 'userlink': 'http://localhost/user/b'}],
        'auditLog': [{
          'action': 'ADD',
          'admin': {'name': 'user.a', 'userlink': 'http://localhost/user/a'},
          'created': '2016-06-28T23:28:29.000Z',
          'member': {'name': 'user.b', 'userlink': 'http://localhost/user/b'}
        }]
      }
    );
  });

  it('should populateServiceData', function() {
    expect(viewUtils.populateServiceData({name: 'service', domainId: 'domainId'}))
      .to.deep.equal({
        'domainId': 'domainId',
        'addKeyUrl': '/athenz/domain/domainId/service/service/key/add',
        'deleteUrl': '/athenz/domain/domainId/service/service/delete',
        'fullName': 'service',
        'name': 'service',
        'user': null
      }
    );
  });

  it('should populatePolicyData', function() {
    expect(viewUtils.populatePolicyData({name: 'policy', domainId: 'domainId'}))
      .to.deep.equal({
        'domainId': 'domainId',
        'addAssertion': '/athenz/domain/domainId/policy/policy/assertion/add',
        'deleteUrl': '/athenz/domain/domainId/policy/policy/delete',
        'fullName': 'policy',
        'name': 'policy'
      }
    );
  });

  it('should moveRole', function() {
    expect(viewUtils.moveRole([{
      name: 'user.domain:role.a10',
      created: '2016-06-28T23:28:29.000Z'
    }, {
      name: 'user.domain:role.admin',
      created: '2016-06-28T23:28:29.000Z'
    }, {
      name: 'user.domain:role.deployer',
      created: '2016-06-28T23:28:29.000Z'
    }, {
      name: 'user.domain:role.reader',
      created: '2016-06-28T23:28:29.000Z'
    }], 'user.domain:role.admin'))
      .to.deep.equal([{
        name: 'user.domain:role.admin',
        created: '2016-06-28T23:28:29.000Z'
      }, {
        name: 'user.domain:role.a10',
        created: '2016-06-28T23:28:29.000Z'
      }, {
        name: 'user.domain:role.deployer',
        created: '2016-06-28T23:28:29.000Z'
      }, {
        name: 'user.domain:role.reader',
        created: '2016-06-28T23:28:29.000Z'
      }]
    );
  });
});
