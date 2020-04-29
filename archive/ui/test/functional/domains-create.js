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

describe('create domains functionality', function() {
  var page = 'athenz/domain/create/domain';

  before(function() {
    return browser.newUser().then(function() {
      return browser.get(page);
    });
  });

  describe('create domain page elements', function() {
    it('should show expected titles and tabs', function() {
      expect($('.app-title').getText()).to.eventually.equal('Create new Domain');
    });

    it('should load search container in the header', function() {
      expect($('.header-container .search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.header-container .search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should load create domains form elements', function() {
      expect($('.create-buttons a:nth-child(1)').getText()).to.eventually.equal('Top Level');
      expect($('.create-buttons a:nth-child(2)').getText()).to.eventually.equal('Sub domain');
      expect($('.create-buttons a:nth-child(3)').getText()).to.eventually.equal('Personal');

      expect($('.content input[name=name]').getAttribute('placeholder')).to.eventually.equal('Enter Domain Name');

      expect($('form .submit-container button:first-child').getText()).to.eventually.equal('Submit');
      expect($('form .submit-container button:nth-child(2)').getText()).to.eventually.equal('Cancel');
    });
  });

});

