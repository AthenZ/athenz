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

var servicesHandler = require('../../../src/api/services');
var sinon = require('sinon');
var expect = require('chai').expect;
var restClient = require('../../config/helpers').restClient;

var sandbox;

describe('services', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('should test fetch services', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getServiceIdentities');
    fetchExpectation.callsArgWith(1, null, {
      list: [
        {
          modified: 'aa',
          name: 'a'
        },
        {
          modified: 'bb',
          name: 'b'
        }
      ]
    });
    var cb = sandbox.spy();

    servicesHandler.fetchServices({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.be.null;
    expect(cbArgs[1]).to.deep.equal([
      {
        modified: 'aa',
        name: 'a'
      },
      {
        modified: 'bb',
        name: 'b'
      }
    ]);
  });

  it('should test fetch services error', function() {
    var fetchExpectation = sandbox.mock(restClient).expects('getServiceIdentities');
    fetchExpectation.callsArgWith(1, 'err');
    var cb = sandbox.spy();

    servicesHandler.fetchServices({}, restClient, cb);

    var cbArgs = cb.args[0];
    expect(cb.calledOnce).to.be.true;
    expect(cbArgs[0]).to.not.be.null;
    expect(cbArgs[1]).to.be.undefined;
  });
});
