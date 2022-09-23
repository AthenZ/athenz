/*
 * Copyright The Athenz Authors
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

let fs = require('fs');
const debug = require('debug')('AthenzUI:server:config');
module.exports = function () {
    let defaultConfig = {};
    try {
        defaultConfig = require(process.cwd() +
            '/src/config/default-config.js')();
    } catch (err) {
        debug('[Startup] default config target does not exist. Moving on.. ');
    }

    let extendedConfig = {};
    try {
        fs.statSync(process.cwd() + '/src/config/extended-config.js');
        extendedConfig = require(process.cwd() +
            '/src/config/extended-config.js')();
    } catch (err) {
        if (err.code !== 'ENOENT') {
            debug('[Startup] Extended config does not exist. Moving on.. ');
        }
    }
    return Object.assign(defaultConfig, extendedConfig);
};
