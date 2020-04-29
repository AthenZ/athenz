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

var pagination = require('../../../src/utils/pagination.js');
var expect = require('chai').expect;


describe('pagination', function() {
  it('should not populate previousPage if first page', function() {
    var params = pagination.populatePages('uri/', 1, 101);
    expect(params.previousPage).to.be.empty;
    expect(params.firstPage).to.be.empty;
    expect(params.nextPage).to.equal('uri/2');
    expect(params.lastPage).to.equal('uri/3');
    expect(params.startItemIndex).to.equal(1);
    expect(params.endItemIndex).to.equal(50);
  });

  it('should not populate previousPage if last page', function() {
    var params = pagination.populatePages('uri/', 3, 101);
    expect(params.firstPage).to.equal('uri/1');
    expect(params.previousPage).to.equal('uri/2');
    expect(params.nextPage).to.be.empty;
    expect(params.lastPage).to.be.empty;
    expect(params.startItemIndex).to.equal(101);
    expect(params.endItemIndex).to.equal(101);
  });

  it('should populate all pages', function() {
    var params = pagination.populatePages('uri/', 2, 101);
    expect(params.firstPage).to.equal('uri/1');
    expect(params.lastPage).to.equal('uri/3');
    expect(params.nextPage).to.equal('uri/3');
    expect(params.previousPage).to.equal('uri/1');
    expect(params.startItemIndex).to.equal(51);
    expect(params.endItemIndex).to.equal(100);
  });

  it('should populate query params', function() {
    var params = pagination.populateQueryParams(2);
    expect(params.start).to.equal(50);
    expect(params.count).to.equal(pagination.perPage);
  });

  it('should populate default query params', function() {
    expect(pagination.populateQueryParams().start).to.equal(0);
  });

  it('should populate params for fetching all', function() {
    expect(pagination.populateQueryParams('all')).to.deep.equal({start: 0, count: 1000000});
  });
});
