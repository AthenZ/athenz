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

var fs = require('fs');

module.exports = function() {
  var defaultConfig = require(process.cwd() + '/config/default-config.js')();
  try {
    fs.statSync(process.cwd() + '/config/extended-config.js');
    var extendedConfig = require(process.cwd() + '/config/extended-config.js')();
  } catch(err) {
    if (err.code !== 'ENOENT') {
      console.log(err);
    }
    var extendedConfig = {};
  }

  var c = Object.assign(defaultConfig, extendedConfig);

  return c;
};
