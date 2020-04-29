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

describe('roles functionality', function() {
  var domain = 'athenz';
  var page = '/athenz/domain/' + domain + '/role';
  //var role = 'admin';

  before(function() {
    return browser.get('/').then(function() {
      return browser.newUser().then(function() {
        return browser.get(page);
      });
    });
  });

  describe('roles page elements', function() {
    it('should show expected titles and tabs', function() {
      expect($('.app-title').getText()).to.eventually.equal('athenz');
      expect($('.app-links .active').getText()).to.eventually.equal('Roles');
      expect($('.app-links .nav-links li:nth-child(2)').getText()).to.eventually.equal('Services');
      expect($('.app-links .nav-links li:nth-child(3)').getText()).to.eventually.equal('Policies');
    });

    it('should load search container in the header', function() {
      expect($('.header-container .search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.header-container .search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should load roles data table', function() {
      expect($('.roles-section .add-container .add-role').getText()).to.eventually.equal('ADD ROLE');
      expect($('.roles-list thead th:first-child').getText()).to.eventually.equal('ROLE');
    });

    it('should show at least one role (admin)', function() {
      expect($$('.roles-list tbody tr[id=admin]').count()).to.eventually.be.at.least(1);
    });
  });

  describe('add roles link', function() {
    it('should show Add role to this domain page', function() {
      //browser.manage().window().setSize(1024, 3000);
      //return $('.roles-section .add-container .add-role').click().then(function() {
      //  return browser.executeScript('document.querySelector(".modal.add-role-modal.visible").scrollIntoView(true)').then(function() {
          //return ($('.modal.add-role-modal').isPresent()).to.eventually.be.true.then(function() {
          //  expect($('.modal.add-role-modal.visible div').getText()).to.eventually.equal('Add role to this domain');
          //});
        //});
      //});
    });
  });

  describe('role: admin - more', function() {
    it('should show role Details page', function() {
      return $('.roles-list tbody tr[id=admin] .icon .icon-more').click().then(function() {
        //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
      });
    });
  });

  describe('role: admin - delete', function() {
    it('should show Delete role icon', function() {
      return $('.roles-list tbody tr[id=admin] .icon .icon-trash').click().then(function() {
        //expect($('.modal .delete-modal .visible .title .message').getText()).to.eventually.equal('Once the Role is deleted it cannot be recovered');
      });
    });
  });

  describe('tabs', function() {
    before(function() {
      return browser.newUser().then(function() {
        return browser.get(page);
      });
    });

    it('should navigate to services page', function() {
      return $('.app-links .nav-links li:nth-child(2) a').click().then(function() {
        expect($('.app-links .active').getText()).to.eventually.equal('Services');
      });
    });

    it('should navigate to policies page', function() {
      return $('.app-links .nav-links li:nth-child(3) a').click().then(function() {
        expect($('.app-links .active').getText()).to.eventually.equal('Policies');
      });
    });
  });
});
