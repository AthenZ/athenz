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
var userRoutes = require('../routeHandlers/user');
var config = require('../../config/config.js')();
var q = require('querystring');
var auth_core = require('@athenz/auth-core');
var authority = new auth_core.PrincipalAuthority();
authority.setKeyStore(require('../PublicKeyStore'));

module.exports = {
  // Sign user token (authorized service token) with service key
  signUserToken: function(app) {
    app.use(function(req, res, next) {
      if (req.body.token && req.body.token !== 'undefined') {
        // Typically key is serviceFQN (ex: athenz.ui)
        var key = './keys/' + req.config.serviceFQN + '.pem';
        var keyVersion = req.config.authKeyVersion;
        var authKey = fs.readFileSync(key, 'utf8');
        if (authKey) {
          req.authSvcToken = userRoutes.signToken(req.body.token, authKey, keyVersion);
        } else {
          console.error('Failed to sign user token, authKey not found');
        }

      // From the second time after login, we are checking the token in cookies
      } else if (req.cookies[config.cookieName]) {
        req.authSvcToken = req.cookies[config.cookieName];

      // Otherwise we should redirect to login page
      } else if (!req.originalUrl.startsWith(config.loginPath)) {
        return res.redirect(config.loginPath + '?redirect=' + q.escape(req.originalUrl));
      }
      next();
    });
  },

  // Authenticate user
  authenticateUser: function(app) {
    app.use(function(req, res, next) {
      if (req.originalUrl.startsWith(config.loginPath)) {
        res.clearCookie(config.cookieName);

      } else if (!req.originalUrl.startsWith('/assets') && !req.originalUrl.startsWith('/favicon')) {

        // Authenticate user with auth_core
        var principal = authority.authenticate(req.authSvcToken, req.ip, req.method);
        if (!principal) {
          return res.redirect(config.loginPath + '?error=1&redirect=' + q.escape(req.originalUrl));
        }

        req.username = (principal.getName() && principal.getName() !== 'undefined') ? principal.getName() : req.config.user;
        req.user = {
          userDomain: req.config.userDomain + '.' + req.username,
          login: req.username
        };

      }

      next();
    });
  },

  // Save cookie
  saveCookie: function(app) {
    app.use(function(req, res, next) {
      if (req.authSvcToken && !req.cookies[config.cookieName]) {
        res.cookie(config.cookieName, req.authSvcToken, {
          maxAge: config.cookieMaxAge,
          httpOnly: true,
          secure: true
        });
      }
      next();
    });
  }
};
