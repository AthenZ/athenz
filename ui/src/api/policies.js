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

var paginationUtils = require('../utils/pagination');

module.exports = {
  fetchPolicies: function(params, restClient, cb) {
    var pageParams = paginationUtils.populateQueryParams('all');
    restClient.getPolicies({
      limit: pageParams.count,
      domainName: params.domainId
    }, function(err, json) {
      if (!err && Array.isArray(json.list)) {
        return cb(null, json.list);
      }
      cb(err);
    });
  }
};
