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

var viewUtils = require('../utils/view');

module.exports = {
  getPageCommonData: function(req, res, cb) {
    var pendingApiCount = 1;

    req.restClient.getDomainList(function(err, json) {
      res.locals.domains = [];
      if (!err && Array.isArray(json.names)) {
        res.locals.domains = json.names;
      }

      viewUtils.callCb(cb, res.locals.domains, --pendingApiCount);
    });
  }
};
