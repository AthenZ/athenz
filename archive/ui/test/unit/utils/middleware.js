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

const middleware = require('../../../src/utils/middleware.js');

const expect = require('chai').expect;
const sinon = require('sinon');

let sandbox;
describe('middleware utils', () => {

  beforeEach(() => {
    // sandbox = sinon.createSandbox();
    sandbox = sinon.sandbox.create();
  });
  afterEach(() => {
    sandbox.restore();
  });

  describe('redirectOnTrailingSlash', () => {

    let req, res, next;
    beforeEach(() => {
      req = {};
      res = {};
      res.redirect = sandbox.spy();
      next = sandbox.spy();
    });

    const restoreFuncs = [];
    before(() => {
      restoreFuncs.push((function(value) {
        if (value) {
          process.env.UI_SERVER = value;
        } else {
          delete process.env.UI_SERVER;
        }
      }).bind(null, process.env.UI_SERVER));
      process.env.UI_SERVER = process.env.UI_SERVER || null;
    });
    after(() => {
      restoreFuncs.forEach(f => f());
    });

    it('single slash, skip', () => {
      req.url = '/';

      middleware.redirectOnTrailingSlash(req, res, next);
      expect(next.callCount).to.equal(1);
    });

    it('no ending slash, skip', () => {
      req.url = '/athenz';

      middleware.redirectOnTrailingSlash(req, res, next);
      expect(next.callCount).to.equal(1);
    });

    it('with ending slash, env. not set, remove and redirect', () => {
      // sandbox.stub(process.env, 'UI_SERVER').value('');
      sandbox.stub(process.env, 'UI_SERVER', '');
      req.url = '/athenz/';

      middleware.redirectOnTrailingSlash(req, res, next);
      expect(res.redirect.callCount).to.equal(1);
      const args = res.redirect.firstCall.args;
      expect(args[0]).to.equal(301);
      expect(args[1]).to.equal('//localhost/athenz');
    });

    it('with ending slash, env. set, remove and redirect', () => {
      // sandbox.stub(process.env, 'UI_SERVER').value('athenz.server.domain');
      sandbox.stub(process.env, 'UI_SERVER', 'athenz.server.domain');
      req.url = '/athenz/';

      middleware.redirectOnTrailingSlash(req, res, next);
      expect(res.redirect.callCount).to.equal(1);
      const args = res.redirect.firstCall.args;
      expect(args[0]).to.equal(301);
      expect(args[1]).to.equal('//athenz.server.domain/athenz');
    });

    it('check open redirect vulnerability', () => {
      req.url = '//example.com/';

      middleware.redirectOnTrailingSlash(req, res, next);
      expect(res.redirect.callCount).to.equal(1);
      const args = res.redirect.firstCall.args;
      expect(args[0]).to.equal(301);
      expect(args[1].startsWith('//example.com'), 'redirect location should not start with another domain').to.false;
    });

  });

});
