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

const config = {
  development: {
    ztshost: process.env.ZTS_SERVER || 'localhost',
    strictSSL: false,
    logLevel: 'debug',
    tokenMinExpiryTime: 900,
    tokenRefresh: 1800,
    disableCache: false
  },
  production: {
    ztshost: process.env.ZTS_SERVER || 'localhost',
    strictSSL: true,
    logLevel: 'info',
    tokenMinExpiryTime: 900,
    tokenRefresh: 1800,
    disableCache: false
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
/* istanbul ignore next */
module.exports = function() {
  let c = config[process.env.SERVICE_NAME || 'development'];

  c.ztshost = c.ztshost || 'localhost';
  c.zts = process.env.ZTS_SERVER_URL || 'https://' + c.ztshost + ':4443/zts/v1/',
  c.strictSSL = c.strictSSL || false;
  c.logLevel = c.logLevel || 'debug';
  c.tokenMinExpiryTime = c.tokenMinExpiryTime || 900;
  c.tokenRefresh = c.tokenRefresh || 1800;
  c.disableCache = c.disableCache || false;

  return c;
};
