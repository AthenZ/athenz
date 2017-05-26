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

var config = {
  development: {
    zmshost: process.env.ZMS_SERVER || 'localhost',
    userDomain: 'user',
    authHeader: 'Athenz-Principal-Auth',
    strictSSL: false,
    user: 'ui',
    serviceFQN: 'athenz.ui',
    authKeyVersion: '0',
    envLabel: '',
    userIcon: function(user) {
      return '/imgs/welcome_to_athenz.gif';
    },
    cookieName: 'Athenz-Principal-Auth',
    cookieMaxAge: (60 * 60 * 1000),
    loginUtils: process.cwd() + '/src/utils/login',
    routesUtils: process.cwd() + '/src/utils/routes',
    clientScript: 'index.js',
    loginPath: '/athenz/login'
  },
  production: {
    zmshost: process.env.ZMS_SERVER || 'localhost',
    userDomain: 'user',
    authHeader: 'Athenz-Principal-Auth',
    strictSSL: true,
    user: 'ui',
    serviceFQN: 'athenz.ui',
    authKeyVersion: '0',
    envLabel: '',
    userIcon: function(user) {
      return '/imgs/welcome_to_athenz.gif';
    },
    cookieName: 'Athenz-Principal-Auth',
    cookieMaxAge: (60 * 60 * 1000),
    loginUtils: process.cwd() + '/src/utils/login',
    routesUtils: process.cwd() + '/src/utils/routes',
    clientScript: 'index.js',
    loginPath: '/athenz/login'
  }
};

// Fetches 'service' specific config sub-section, and fills defaults if not present
module.exports = function() {
  var c = config[process.env.SERVICE_NAME || 'development'];

  c.zmshost = c.zmshost || 'localhost';
  c.zms = process.env.ZMS_SERVER_URL || 'https://' + c.zmshost + ':4443/zms/v1/',
  c.userDomain = c.userDomain || 'user';
  c.authHeader = c.authHeader || 'Athenz-Principal-Auth';
  c.strictSSL = c.strictSSL || false;
  c.user = c.user || 'ui';
  c.serviceFQN = c.serviceFQN || process.env.DOMAIN_NAME + '.' + process.env.SERVICE_NAME;
  c.authKeyVersion = c.authKeyVersion || '0';
  c.envLabel = c.envLabel || 'development';
  c.userIcon = c.userIcon || function(user) {
    return '/imgs/welcome_to_athenz.gif';
  };
  c.cookieName = c.cookieName || 'Athenz-Principal-Auth';
  c.cookieMaxAge = c.cookieMaxAge || (60 * 60 * 1000);
  c.loginUtils = c.loginUtils || process.cwd() + '/src/utils/login';
  c.routesUtils = c.routesUtils || process.cwd() + '/src/utils/routes';
  c.clientScript = c.clientScript || 'index.js';
  c.loginPath = c.loginPath || '/athenz/login';

  return c;
};
