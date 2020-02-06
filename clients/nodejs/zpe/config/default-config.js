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
    logLevel: 'debug',
    policyDir: '/home/athenz/var/zpe',
    confFileName: '/home/athenz/conf/athenz/athenz.conf',
    tokenRefresh: 1800,
    policyRefresh: 1800,
    allowedOffset: 300,
    disableCache: false,
    updater: './ZPEUpdater',
    disableWatch: true
  },
  production: {
    logLevel: 'info',
    policyDir: '/home/athenz/var/zpe',
    confFileName: '/home/athenz/conf/athenz/athenz.conf',
    tokenRefresh: 1800,
    policyRefresh: 1800,
    allowedOffset: 300,
    disableCache: false,
    updater: './ZPEUpdater',
    disableWatch: true
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
/* istanbul ignore next */
module.exports = function() {
  let c = config[process.env.SERVICE_NAME || 'development'];

  c.logLevel = c.logLevel || 'debug';
  c.policyDir = c.policyDir || '/home/athenz/var/zpe';
  c.confFileName = c.confFileName || '/home/athenz/conf/athenz/athenz.conf';
  c.tokenRefresh = c.tokenRefresh || 1800;
  c.policyRefresh = c.policyRefresh || 1800;
  c.allowedOffset = c.allowedOffset || 300;
  c.disableCache = c.disableCache || false;
  c.updater = c.updater || './ZPEUpdater';
  c.disableWatch = c.disableWatch || false;

  return c;
};
