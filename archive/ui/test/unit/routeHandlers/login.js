/**
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

var routeHandlers = require('../../../src/routeHandlers/login');
var config = require('../../../config/config.js')();

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

  it('should test notLogged route for non ajax context', function() {
    req.originalUrl = 'dummy';
    req.method = 'GET';
		req.config = config;

    var mock = sandbox.mock(res);
    mock.expects('render').withArgs('login', {
      pageTitle: 'Athenz UI login page',
      redirect: "/athenz",
      target: '/athenz/login',
      url: 'dummy'
    });

    routeHandlers.notLogged(req, res);
     
    mock.verify();
  });

  it('should test notLogged route for ajax context', function() {
    req.originalUrl = 'ajax';

    var mock = sandbox.mock(res);
    mock.expects('status').withArgs(401).returns(res);
    mock.expects('send').withArgs('');

    routeHandlers.notLogged(req, res);

    mock.verify();
  });

});
