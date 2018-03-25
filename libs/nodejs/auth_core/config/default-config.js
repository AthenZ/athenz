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
    principalIpCheckMode: 'OPS_WRITE',
    principalTokenAllowedOffset: '300',
    principalUserDomain: 'user',
    principalHeader: 'Athenz-Principal-Auth',
    roleTokenAllowedOffset: '300',
    roleUserDomain: 'user',
    roleHeader: 'Athenz-Role-Auth',
    tokenMaxExpiry: String(30 * 24 * 60 * 60),
    tokenNoExpiry: false,
    logLevel: 'debug'
  },
  production: {
    principalIpCheckMode: 'OPS_WRITE',
    principalTokenAllowedOffset: '300',
    principalUserDomain: 'user',
    principalHeader: 'Athenz-Principal-Auth',
    roleTokenAllowedOffset: '300',
    roleUserDomain: 'user',
    roleHeader: 'Athenz-Role-Auth',
    tokenMaxExpiry: String(30 * 24 * 60 * 60),
    tokenNoExpiry: false,
    logLevel: 'info'
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
/* istanbul ignore next */
module.exports = function() {
  let c = config[process.env.SERVICE_NAME || 'development'];

  c.principalIpCheckMode = c.principalIpCheckMode || 'OPS_WRITE';
  c.principalTokenAllowedOffset = c.principalTokenAllowedOffset || '300';
  c.principalUserDomain = c.principalUserDomain || 'user';
  c.principalHeader = c.principalHeader || 'Athenz-Principal-Auth';
  c.roleTokenAllowedOffset = c.roleTokenAllowedOffset || '300';
  c.roleUserDomain = c.roleUserDomain || 'user';
  c.roleHeader = c.roleHeader || 'Athenz-Role-Auth';
  c.tokenMaxExpiry = c.tokenMaxExpiry || String(30 * 24 * 60 * 60);
  c.tokenNoExpiry = c.tokenNoExpiry || false;
  c.logLevel = c.logLevel || 'info';

  return c;
};
