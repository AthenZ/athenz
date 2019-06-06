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

const config = require('../../config/config.js')();

const redirectOnTrailingSlash = (req, res, next) => {
  if (req.url.substr(-1) === '/' && req.url.length > 1) {
    const domain = process.env.UI_SERVER || 'localhost';
    res.redirect(301, '//' + domain + req.url.slice(0, -1));
  } else {
    next();
  }
};

module.exports = {
  redirectOnTrailingSlash,
};
