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
    timeZone: 'America/Los_Angeles',
    language: 'en-US',
    zmshost: process.env.ZMS_SERVER || 'localhost',
    userDomain: 'user',
    authHeader: 'Athenz-Principal-Auth',
    strictSSL: false,
    user: 'ui-server',
    serviceFQN: 'athenz.ui-server',
    authKeyVersion: '0',
    envLabel: '',
    userIcon: function(user) {
      return '/imgs/welcome_to_athenz.gif';
    },
    userLink: function (user) {
      const domain = process.env.UI_SERVER || 'localhost';
      return 'https://' + domain + ':443/athenz/domain/create/userdomain';
    },
    headerLinks: [
      {title: 'Website', url: 'http://www.athenz.io', target: '_blank'},
      {title: 'Getting Started', url: 'https://github.com/yahoo/athenz/blob/master/README.md', target: '_blank'},
      {title: 'Documentation', url: 'https://github.com/yahoo/athenz/blob/master/README.md', target: '_blank'},
      {title: 'GitHub', url: 'https://github.com/yahoo/athenz', target: '_blank'},
      {title: 'Suggest', url: 'https://github.com/yahoo/athenz/issues', target: '_blank'},
      {title: 'Contact Us', url: 'http://www.athenz.io/contact.html', target: '_blank'},
      {title: 'Blog', url: 'https://www.tumblr.com/blog/athenz-security', target: '_blank'},
      {title: 'Logout', url: '/athenz/login', target: ''}
    ],
    cookieName: 'Athenz-Principal-Auth',
    cookieMaxAge: (60 * 60 * 1000),
    loginUtils: process.cwd() + '/src/utils/login',
    routesUtils: process.cwd() + '/src/utils/routes',
    clientScript: 'index.js',
    loginPath: '/athenz/login'
  },
  production: {
    timeZone: 'America/Los_Angeles',
    language: 'en-US',
    zmshost: process.env.ZMS_SERVER || 'localhost',
    userDomain: 'user',
    authHeader: 'Athenz-Principal-Auth',
    strictSSL: true,
    user: 'ui-server',
    serviceFQN: 'athenz.ui-server',
    authKeyVersion: '0',
    envLabel: '',
    userIcon: function(user) {
      return '/imgs/welcome_to_athenz.gif';
    },
    userLink: function (user) {
      const domain = process.env.UI_SERVER || 'localhost';
      return 'https://' + domain + ':443/athenz/domain/create/userdomain';
    },
    headerLinks: [
      {title: 'Website', url: 'http://www.athenz.io', target: '_blank'},
      {title: 'Getting Started', url: 'https://github.com/yahoo/athenz/blob/master/README.md', target: '_blank'},
      {title: 'Documentation', url: 'https://github.com/yahoo/athenz/blob/master/README.md', target: '_blank'},
      {title: 'GitHub', url: 'https://github.com/yahoo/athenz', target: '_blank'},
      {title: 'Suggest', url: 'https://github.com/yahoo/athenz/issues', target: '_blank'},
      {title: 'Contact Us', url: 'http://www.athenz.io/contact.html', target: '_blank'},
      {title: 'Blog', url: 'https://www.tumblr.com/blog/athenz-security', target: '_blank'},
      {title: 'Logout', url: '/athenz/login', target: ''}
    ],
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
  let c = config[process.env.SERVICE_NAME || 'development'];

  c.zmshost = c.zmshost || 'localhost';
  c.zms = process.env.ZMS_SERVER_URL || 'https://' + c.zmshost + ':4443/zms/v1/';
  c.zms_ajax = process.env.ZMS_AJAX_URL || c.zms;
  c.userDomain = c.userDomain || 'user';
  c.authHeader = c.authHeader || 'Athenz-Principal-Auth';
  c.strictSSL = c.strictSSL || false;
  c.user = c.user || 'ui-server';
  c.serviceFQN = c.serviceFQN || process.env.DOMAIN_NAME + '.' + process.env.SERVICE_NAME;
  c.authKeyVersion = c.authKeyVersion || '0';
  c.envLabel = c.envLabel || 'development';
  c.userIcon = c.userIcon || function(user) {
    return '/imgs/welcome_to_athenz.gif';
  };
  c.userLink = c.userLink || function(user) {
    const domain = process.env.UI_SERVER || 'localhost';
    return 'https://' + domain + '/athenz/domain/create/userdomain';
  };
  c.cookieName = c.cookieName || 'Athenz-Principal-Auth';
  c.cookieMaxAge = c.cookieMaxAge || (60 * 60 * 1000);
  c.loginUtils = c.loginUtils || process.cwd() + '/src/utils/login';
  c.routesUtils = c.routesUtils || process.cwd() + '/src/utils/routes';
  c.clientScript = c.clientScript || 'index.js';
  c.loginPath = c.loginPath || '/athenz/login';

  return c;
};
