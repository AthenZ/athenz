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

describe('search functionality', function() {
  var page = '/';

  before(function() {
    return browser.newUser().then(function() {
      return browser.get(page);
    });
  });

  describe('search usecases', function() {
    it('should show search container', function() {
      expect($('.search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should show all domains', function() {
      return $('.search-container button').click().then(function() {
        expect($('.domain-list .desc').getText()).to.eventually.equal('Search Results');
        expect($$('.domain-list .search-results tr').count()).to.eventually.be.at.least(1);
        return $('.domain-list .search-results tr:first-child td a').getText().then(function(firstDomain) {
          $('.domain-list .search-results tr:first-child td a').click().then(function() {
            expect($('.app-title').getText()).to.eventually.equal(firstDomain);
            expect($('.app-links .active').getText()).to.eventually.equal('Roles');
            expect($('.app-links .nav-links li:nth-child(2)').getText()).to.eventually.equal('Services');
            expect($('.app-links .nav-links li:nth-child(3)').getText()).to.eventually.equal('Policies');
          });
        });
      });
    });

    it('should return search results', function() {
      $('.search-container .search input').value = 'athenz';
      return $('.search-container button').click().then(function() {
        expect($('.domain-list .desc').getText()).to.eventually.equal('Search Results');
        expect($$('.domain-list .search-results tr').count()).to.eventually.be.at.least(1);
        return $('.domain-list .search-results tr:first-child td a').getText().then(function(firstDomain) {
          $('.domain-list .search-results tr:first-child td a').click().then(function() {
            expect($('.app-title').getText()).to.eventually.equal(firstDomain);
            expect($('.app-links .active').getText()).to.eventually.equal('Roles');
            expect($('.app-links .nav-links li:nth-child(2)').getText()).to.eventually.equal('Services');
            expect($('.app-links .nav-links li:nth-child(3)').getText()).to.eventually.equal('Policies');
          });
        });
      });
    });
  });
});
