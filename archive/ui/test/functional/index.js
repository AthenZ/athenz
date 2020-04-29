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

describe('index page', function() {

  it('should allow a logged in user', function() {
    return browser.newUser().then(function() {
      return browser.get('/').then(function() {
        return browser.getTitle().then(function(title) {
          assert.equal(title, 'Athenz Viewer :: Home');
        });
      });
    });
  });

  describe('search form and other UI elements', function() {
    it('should show search container on the main panel area', function() {
      expect($('.search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should show Add Domains links that works', function() {
      expect($('.domains .create a').getText()).to.eventually.equal('Create a domain');
      $('.domains .create a').click().then(function() {
        expect($('.app-title').getText()).to.eventually.equal('Create new Domain');
      });
    });

    it('should show My Domains section', function() {
      expect($('.domains .title span:nth-of-type(1)').getText()).to.eventually.equal('My Domains');
    });

    it('should show Manage link that works', function() {
      expect($('.domains .title span:nth-of-type(2) a').getText()).to.eventually.equal('Manage');
      return $('.domains .title span:nth-of-type(2) a').click().then(function() {
        expect($('.app-title').getText()).to.eventually.equal('Manage My Domains');
      });
    });

    it('should show entries in My Domains that work', function() {
      expect($$('.domains ul li').count()).to.eventually.be.at.least(1);
      return $('.domains ul li:first-child a').getText().then(function(firstDomain) {
        return $('.domains ul li:first-child a').click().then(function() {
          expect($('.app-title').getText()).to.eventually.equal(firstDomain);
          expect($('.app-links .active').getText()).to.eventually.equal('Roles');
          expect($('.app-links .nav-links li:nth-child(2)').getText()).to.eventually.equal('Services');
          expect($('.app-links .nav-links li:nth-child(3)').getText()).to.eventually.equal('Policies');
        });
      });
    });
  });
});
