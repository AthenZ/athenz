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
var config = {
  development: {
    zms: process.env.ZMS_SERVER_URL || 'https://localhost:4443/zms/v1/',
    strictSSL: false,
    user: 'ui',
    serviceFQN: 'athenz.ui',
    authKeyVersion: '0',
    envLabel: ''
  },
  production: {
    zms: process.env.ZMS_SERVER_URL || 'https://localhost:4443/zms/v1/',
    strictSSL: true,
    user: 'ui',
    serviceFQN: 'athenz.ui',
    authKeyVersion: '0',
    envLabel: ''
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
module.exports = function() {
  var c = config[process.env.SERVICE_NAME || 'development'];

  c.user = c.user || 'ui';
  c.serviceFQN = c.serviceFQN || process.env.DOMAIN_NAME + '.' + process.env.SERVICE_NAME;
  c.authKeyVersion = c.authKeyVersion || '0';

  return c;
};
