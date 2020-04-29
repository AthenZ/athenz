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

describe('manage domains functionality', function() {
  var page = '/athenz/domain/manage';

  before(function() {
    return browser.newUser().then(function() {
      return browser.get(page);
    });
  });

  describe('manage domain page elements', function() {
    it('should show expected titles and tabs', function() {
      expect($('.app-title').getText()).to.eventually.equal('Manage My Domains');
    });

    it('should load search container in the header', function() {
      expect($('.header-container .search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.header-container .search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should load domains data table', function() {
      expect($('.domain-list thead th:first-child').getText()).to.eventually.equal('NAME');
    });

    it('should show at least one domain', function() {
      expect($$('.domain-list tbody tr').count()).to.eventually.be.at.least(1);
    });
  });

  describe('domain: more', function() {
    it('should show domain Details page', function() {
      return $('.domain-list tbody tr:first-child .icon .icon-more').click().then(function() {
        //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
      });
    });
  });

  describe('domain: edit', function() {
    it('should show Edit form', function() {
      return $('.domain-list tbody tr:first-child .icon .icon-edit').click().then(function() {
        //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
      });
    });
  });

/*
  describe('domain: delete', function() {
    it('should show Delete domain icon', function() {
      return $('.domain-list tbody tr:first-child .icon .delete-domain').click().then(function() {
        //expect($('.modal .delete-modal .visible .title .message').getText()).to.eventually.equal('Once the Policy is deleted it cannot be recovered');
      });
    });
  });
*/
});
