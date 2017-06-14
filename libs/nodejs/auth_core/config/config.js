/**
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
  var defaultConfig = require('./default-config.js')();
  var extendedConfig;
  var userConfig;
  if (__dirname !== process.cwd() + '/config') {
    var parentModule = module.parent;
    while (parentModule.id.match(/node_modules\/auth_core\//)) {
      parentModule = parentModule.parent;
    }
    var module_path = parentModule.id.match(/(.*)(node_modules\/(\w+))/g);
    try {
      fs.statSync(module_path + '/config/config.js');
      extendedConfig = require(module_path + '/config/config.js');
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(err);
      }
    }
    try {
      fs.statSync(process.cwd() + '/config/config.js');
      userConfig = require(process.cwd() + '/config/config.js')();
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(err);
      }
    }
  }
  var extendedConfigObj = (extendedConfig) ? extendedConfig().auth_core : {};
  var userConfigObj = (userConfig) ? userConfig().auth_core : {};
  return Object.assign(defaultConfig, extendedConfigObj, userConfigObj);
};
