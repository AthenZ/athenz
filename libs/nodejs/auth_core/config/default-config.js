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

var config = {
  development: {
    principalIpCheckMode: 'OPS_WRITE',
    principalTokenAllowedOffset: '300',
    principalUserDomain: 'user',
    principalHeader: 'Athenz-Principal-Auth',
    tokenMaxExpiry: String(30 * 24 * 60 * 60),
    tokenNoExpiry: true,
    loglebel: 'debug'
  },
  production: {
    principalIpCheckMode: 'OPS_WRITE',
    tokenAllowedOffset: '300',
    userDomain: 'user',
    principalHeader: 'Athenz-Principal-Auth',
    tokenMaxExpiry: String(30 * 24 * 60 * 60),
    tokenNoExpiry: false,
    loglebel: 'info'
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
module.exports = function() {
  var c = config[process.env.SERVICE_NAME || 'development'];

  c.principalIpCheckMode = c.principalIpCheckMode || 'OPS_WRITE';
  c.principalTokenAllowedOffset = c.principalTokenAllowedOffset || '300';
  c.principalUserDomain = c.principalUserDomain || 'user';
  c.principalHeader = c.principalHeader || 'Athenz-Principal-Auth';
  c.tokenMaxExpiry = c.tokenMaxExpiry || String(30 * 24 * 60 * 60);
  c.tokenNoExpiry = c.tokenNoExpiry || false;
  c.loglevel = c.loglevel || 'info';

  return c;
};
