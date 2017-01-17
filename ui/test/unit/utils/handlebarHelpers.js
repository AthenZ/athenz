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

var helpers = require('../../../src/utils/handlebarHelpers');
var sinon = require('sinon');
var expect = require('chai').expect;

var sandbox;

describe('handlebarhelper  utils', function() {
  beforeEach(function() {
    sandbox = sinon.sandbox.create();
  });

  it('should do JSON stringify', function() {
    expect(helpers.json()).to.equal('""');
    expect(helpers.json({a: 'b'})).to.equal('{"a":"b"}');
  });

  it('should add /add to end of url', function() {
    expect(helpers.addToUriPath('abc', 'add')).to.equal('abc/add');
  });

  it('should add query param to url', function() {
    expect(helpers.addToUriQuery('abc', 'type', 'role')).to.equal('abc?type=role');
    expect(helpers.addToUriQuery('abc?x=y', 'type', 'role')).to.equal('abc?x=y&type=role');
  });

  it('should render a select box with blank option', function() {
    var ouput = helpers.renderSelect('test', [{key: 'key', value: 'value'}], true);
    expect(ouput).to.equal(
      '<select name="test" id="test">' +
      '<option></option><option value="key">value</option>' +
      '</select>'
    );
  });

  it('should render a select box with required set', function() {
    var ouput = helpers.renderSelect('test', [{key: 'key', value: 'value'}], true, 'required');
    expect(ouput).to.equal(
      '<select name="test" id="test" required>' +
      '<option></option><option value="key">value</option>' +
      '</select>'
    );
  });

  it('should render a select box with no blank option', function() {
    var ouput = helpers.renderSelect('test', [{key: 'key', value: 'value'}]);
    expect(ouput).to.equal(
      '<select name="test" id="test">' +
      '<option value="key">value</option>' +
      '</select>'
    );

    ouput = helpers.renderSelect('test');
    expect(ouput).to.equal('<select name="test" id="test"></select>');
  });

  it('should render checkboxes', function() {
    var ouput = helpers.renderCheckBoxes('name', [{key: 'key', value: 'value'}]);
    expect(ouput).to.equal(
      '<label><input id="name" name="name" type="checkbox" value="key"/><span class="icon-checkbox">value</span></label>'
    );
  });

  it('should render radio buttons', function() {
    var ouput = helpers.renderRadioButtons('name', [{key: 'key', value: 'value'}]);
    expect(ouput).to.equal(
      '<label><input id="name" name="name" type="radio" value="key"/><span class="icon-radio">value</span></label>'
    );
  });

  it('should render status th with Status if items have status text', function() {
    expect(helpers.renderStatusColumn([{statusText: 'boo'}])).to.equal('<th>Status</th>');
  });

  it('should render status th without Status if items have no status text', function() {
    expect(helpers.renderStatusColumn([{statusText: ''}])).to.equal('<th></th>');
  });

  it('should get odd class for even numbers', function() {
    expect(helpers.getRowClass(2)).to.equal('odd');
  });

  it('should get empty resonse for odd numbers', function() {
    expect(helpers.getRowClass(3)).to.equal('even');
  });

  it('should test formatDate', function() {
    expect(helpers.formatDate()).to.equal('');
    expect(helpers.formatDate('2016-06-29T00:14:36.079Z')).to.equal('6/28/2016, 17:14 PDT');
  });

  it('ifFirstRow helper should render if block for first row', function() {
    var trueSpy = sandbox.spy(),
      falseSpy = sandbox.spy();

    var options = {fn: trueSpy, inverse: falseSpy};
    helpers.ifFirstRow(0, options);
    expect(trueSpy.calledOnce).to.be.true;
    expect(falseSpy.calledOnce).to.be.false;
  });

  it('ifFirstRow helper should render else block for non first rows', function() {
    var trueSpy = sandbox.spy(),
      falseSpy = sandbox.spy();

    var options = {fn: trueSpy, inverse: falseSpy};
    helpers.ifFirstRow(1, options);
    expect(trueSpy.calledOnce).to.be.false;
    expect(falseSpy.calledOnce).to.be.true;
  });

  it('should test number formatter', function() {
    expect(helpers.formatNumber()).to.equal('');
    expect(helpers.formatNumber(null, 'boo')).to.equal('boo');
    expect(helpers.formatNumber(null, {})).to.equal('');
    expect(helpers.formatNumber('2477')).to.equal('2,477');
    expect(helpers.formatNumber('1.2233333')).to.equal('1.22');
  });

  it('should test lowerCase helper', function() {
    expect(helpers.lowerCase()).to.equal('');
    expect(helpers.lowerCase('Role')).to.equal('role');
  });

  it('should test getHome', function() {
    expect(helpers.getHome('blah')).to.equal('/athenz');
    expect(helpers.getHome('blah/dashboard')).to.equal('/athenz');
  });

  it('shoul dtest ifShowDeleteDomainIcon', function() {
    var options = {
      fn: function() {
        return 'fn';
      },
      inverse: function() {
        return 'inverse';
      }
    };

    expect(helpers.ifShowDeleteDomainIcon(true, 'Sub domain', options)).to.equal('fn');
    expect(helpers.ifShowDeleteDomainIcon(false, 'Sub domain', options)).to.equal('inverse');
  });
});
