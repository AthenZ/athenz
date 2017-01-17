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

var _ = require('lodash');

var reqUtils = require('../utils/req');
var domainHandler = require('../api/domain');
var paginationUtils = require('../utils/pagination');

module.exports = {
  searchResultsPage: function(req, res) {
    var pageUri = '/athenz/search/?query=' + encodeURIComponent(req.query.query),
      viewData = {
        pageTitle: 'Search Results',
        initialQueryPage: pageUri + '&page=1',
        searchQuery: req.query.query,
        searchResults: [],
        msg: '',
        noHeaderSearch: true
      };

    domainHandler.fetchAllDomains({}, req.restClient, function(err, data) {
      if (err) {
        reqUtils.populateAppContextErrorMessage(res.locals, err);
      } else if (!err && data) {
        var query = req.query.query;

        data.forEach(function(domainName) {
          if (domainName.includes(query)) {
            viewData.searchResults.push({
              name: domainName
            });
          }
        });
      }

      viewData.totalCount = viewData.searchResults.length;

      viewData.pagination = paginationUtils.populatePages(
        pageUri + '&page=',
        req.query.page,
        viewData.totalCount
      );

      res.locals.domains.forEach(function(userDomain) {
        var searchData = _.find(viewData.searchResults, {name: userDomain.name});
        if(searchData) {
          searchData.userAdminDomain = userDomain.admin;
          searchData.userDomain = true;
        }
      });

      if (viewData.searchResults.length === 0) {
        viewData.msg = 'There were no results for your query.';
      }

      return res.render('searchresults', viewData);
    });
  }
};
