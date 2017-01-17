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

describe('policies functionality', function() {
  var domain = 'athenz';
  var page = '/athenz/domain/' + domain + '/policy';
  //var policy = 'admin';

  before(function() {
    return browser.newUser().then(function() {
      return browser.get(page);
    });
  });

  describe('policies page elements', function() {
    it('should show expected titles and tabs', function() {
      expect($('.app-title').getText()).to.eventually.equal('athenz');
      expect($('.app-links .nav-links li:nth-child(1)').getText()).to.eventually.equal('Roles');
      expect($('.app-links .nav-links li:nth-child(2)').getText()).to.eventually.equal('Services');
      expect($('.app-links .active').getText()).to.eventually.equal('Policies');
    });

    it('should load search container in the header', function() {
      expect($('.header-container .search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.header-container .search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should load policies data table', function() {
      expect($('.policies-section .add-container .add-policy').getText()).to.eventually.equal('ADD A POLICY');
      expect($('.list thead th:first-child').getText()).to.eventually.equal('POLICY');
    });

    it('should show at least one policy (admin)', function() {
      expect($$('.list tbody tr[id=admin]').count()).to.eventually.be.at.least(1);
    });
  });

  describe('add policies link', function() {
    it('should show Add policy to this domain page', function() {
      return $('.policies-section .add-container button').click().then(function() {
        //browser.driver.switchTo().activeElement();
        //expect($('.add-policy-modal div').getText()).to.eventually.equal('Add policy to this role');
      });
    });
  });

  //describe('policy: admin - add rule', function() {
  //  it('should show Add rule form', function() {
  //    return $('.list tbody tr[id=admin] .icon .icon-trust').click().then(function() {
  //      //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
  //    });
  //  });
  //});

  //describe('policy: admin - more', function() {
  //  it('should show policy Details page', function() {
  //    return $('.list tbody tr[id=admin] .icon .icon-more').click().then(function() {
  //      //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
  //    });
  //  });
  //});

  //describe('policy: admin - delete', function() {
  //  it('should show Delete policy icon', function() {
  //    return $('.list tbody tr[id=admin] .icon .delete-policy').click().then(function() {
  //      //expect($('.modal .delete-modal .visible .title .message').getText()).to.eventually.equal('Once the Policy is deleted it cannot be recovered');
  //    });
  //  });
  //});

  describe('tabs', function() {
    before(function() {
      return browser.newUser().then(function() {
        return browser.get(page);
      });
    });

    it('should navigate to roles page', function() {
      return $('.app-links .nav-links li:nth-child(1) a').click().then(function() {
        expect($('.app-links .active').getText()).to.eventually.equal('Roles');
      });
    });

    it('should navigate to services page', function() {
      return $('.app-links .nav-links li:nth-child(2) a').click().then(function() {
        expect($('.app-links .active').getText()).to.eventually.equal('Services');
      });
    });
  });
});
