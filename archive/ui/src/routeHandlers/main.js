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

var NodeRestClient = require('node-rest-client').Client;
var _ = require('lodash');

var pageUtils = require('../utils/page');
var reqUtils = require('../utils/req');
var domainRoutes = require('./domain');
var domainHandler = require('../api/domain');

function notFound(req, res) {
  if(req.method === 'GET' && req.originalUrl.indexOf('ajax') === -1) {
    return res.render('404', {
      pageTitle: '404 Not Found',
      url: req.originalUrl
    });
  }
  res.status(404).send('');
}

module.exports = {
  init: function(req, res, next) {
    pageUtils.initCommonData(req, res);
    res.locals.domains = [];

    domainHandler.fetchUserDomains({
      userId: req.user.userDomain
    }, req.restClient, function(err, data) {
      if (err) {
        reqUtils.populateAppContextErrorMessage(res.locals, err);
      } else if(!err && Array.isArray(data)) {
        res.locals.domains = data;
        var current = _.find(data, {name: req.params.domainId});
        if(current) {
          current.active = 'active';
        }
      }

      if (res.locals.domains.length === 0) {
        res.locals.noDomains =
            'You do not have any domains that you belong to or are an admin of.';
      }

      next();
    });
  },
  redirect: function(req, res) {
    res.redirect('/athenz');
  },
  home: function(req, res) {
    var viewData = {
      pageTitle: 'Home',
      noHeaderSearch: true
    };

    res.render('home', viewData);
  },
  manageDomains: function(req, res) {
    var apiCount = res.locals.domains.length | 0;

    var viewData = {
      pageTitle: 'Manage Domains',
      manageDomainActive: 'active',
      section: {id: 'Manage My Domains'}
    };

    var apiCb = function(count) {
      if(count === 0) {
        pageUtils.setAppContextMessage(req, res);
        res.render('managedomains', viewData);
      }
    };

    if (res.locals.domains.length > 0) {
      res.locals.domains.forEach(function(domain){
        domainHandler.fetchDomainMetadata({
          domainId: domain.name
        },
        req.restClient,
        function(err, result) {
          domain.domainDetails = {};
          if (err) {
            reqUtils.populateAppContextErrorMessage(res.locals, err);
          } else {
            _.assign(domain.domainDetails, result);
          }
          apiCb(--apiCount, err);
        });
      });
    }
  },
  domainRoutes: function(req, res) {
    domainRoutes.domainDetails(req, res, function() {
      switch (req.params.section) {
        case 'role':
          return domainRoutes.roleRoute(req, res);
        case 'service':
          return domainRoutes.serviceRoute(req, res);
        case 'policy':
          return domainRoutes.policyRoute(req, res);
        default:
          notFound(req, res);
      }
    });
  },
  notFound: notFound
};
