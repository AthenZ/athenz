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

describe('services functionality', function() {
  var domain = 'athenz';
  var page = '/athenz/domain/' + domain + '/service';
  //var service = 'syncer';

  before(function() {
    return browser.newUser().then(function() {
      return browser.get(page);
    });
  });

  describe('services page elements', function() {
    it('should show expected titles and tabs', function() {
      expect($('.app-title').getText()).to.eventually.equal('athenz');
      expect($('.app-links .nav-links li:nth-child(1)').getText()).to.eventually.equal('Roles');
      expect($('.app-links .active').getText()).to.eventually.equal('Services');
      expect($('.app-links .nav-links li:nth-child(3)').getText()).to.eventually.equal('Policies');
    });

    it('should load search container in the header', function() {
      expect($('.header-container .search-container .search input').getAttribute('name')).to.eventually.equal('query');
      expect($('.header-container .search-container button').getAttribute('type')).to.eventually.equal('submit');
    });

    it('should load services data table', function() {
      expect($('.services-section .add-container .add-service').getText()).to.eventually.equal('ADD A SERVICE');
      expect($('.list thead th:first-child').getText()).to.eventually.equal('SERVICE');
    });

    it('should show at least one service (admin)', function() {
      expect($$('.list tbody tr[id=syncer]').count()).to.eventually.be.at.least(1);
    });
  });

  describe('add services link', function() {
    it('should show Add service to this domain page', function() {
      return $('.services-section .add-container button').click().then(function() {
        //browser.driver.switchTo().activeElement();
        //expect($('.add-service-modal div').getText()).to.eventually.equal('Add service to this domain');
      });
    });
  });

  //describe('service: syncer - add key', function() {
  //  it('should show Add key form', function() {
  //    return $('.list tbody tr[id=syncer] .icon .icon-key').click().then(function() {
  //      //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
  //    });
  //  });
  //});

  //describe('service: syncer - more', function() {
  //  it('should show service Details page', function() {
  //    return $('.list tbody tr[id=syncer] .icon .icon-more').click().then(function() {
  //      //expect($('.info[id=admin-info] div:first-child').getText()).to.eventually.equal('Members');
  //    });
  //  });
  //});

  //describe('service: syncer - delete', function() {
  //  it('should show Delete service icon', function() {
  //    return $('.list tbody tr[id=syncer] .icon .delete-service').click().then(function() {
  //      //expect($('.modal .delete-modal .visible .title .message').getText()).to.eventually.equal('Once the Service is deleted it cannot be recovered');
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

    it('should navigate to policies page', function() {
      return $('.app-links .nav-links li:nth-child(3) a').click().then(function() {
        expect($('.app-links .active').getText()).to.eventually.equal('Policies');
      });
    });
  });
});
