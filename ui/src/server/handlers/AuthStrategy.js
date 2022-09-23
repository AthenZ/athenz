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
const passport = require('passport-strategy');
const util = require('util');
const auth_core = require('@athenz/auth-core');
const authority = new auth_core.PrincipalAuthority();
authority.setKeyStore(require('./PublicKeyStore'));
const q = require('querystring');
const fs = require('fs');
const crypto = require('crypto');
const debug = require('debug')('AthenzUI:server:strategies:AuthStrategy');

// Helper functions for User Authentication
function signToken(token, authKey, version) {
    const data = token + ';bk=' + version;
    let pk = crypto.createSign('sha256');
    pk.update(data);
    let sig = pk.sign(authKey, 'base64', 'base64');

    // This is to put the 'y' in 'ybase64'
    sig = sig.replace(/\+/g, '.');
    sig = sig.replace(/\//g, '_');
    sig = sig.replace(/=/g, '-');

    return data + ';bs=' + sig;
}

/**
 * `Strategy` constructor.
 *
 * @param expressApp
 * @param config
 * @param secrets
 * @param timeout
 * @api public
 */
function Strategy(expressApp, config, secrets) {
    // initial set up with config
    passport.Strategy.call(this);
    this.name = 'ui-auth';

    // Typically key is serviceFQN (ex: athenz.ui)
    const key = 'keys/' + config.athenzDomainService + '.pem';
    this.keyVersion = config.authKeyVersion;
    this.authKey = fs.readFileSync(key, 'utf8');
    this.cookieName = config.cookieName;
    this.loginPath = config.loginPath;
    this.userDomain = config.userDomain;
    this.user = config.user;
    this.cookieMaxAge = config.cookieMaxAge;
    this.authHeader = config.authHeader;

    debug('[Startup] done configuring AuthStrategy');
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request after coming back from Okta Validator
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
    // check for the cookie first for auth secure cookie, if found set the
    // auth service token
    if (req.cookies[this.cookieName]) {
        req.authSvcToken = req.cookies[this.cookieName];
    } else if (req.headers.token && req.headers.token !== 'undefined') {
        if (this.authKey) {
            req.authSvcToken = signToken(
                req.headers.token,
                this.authKey,
                this.keyVersion
            );
        } else {
            console.error('Failed to sign user token, authKey not found');
        }
    }

    if (req.originalUrl.startsWith(this.loginPath)) {
        req.clearCookie = true;
    } else if (
        !req.originalUrl.startsWith('/_next') &&
        !req.originalUrl.startsWith('/static')
    ) {
        // Authenticate user with auth_core
        const principal = authority.authenticate(
            req.authSvcToken,
            req.ip,
            req.method
        );
        if (!principal) {
            debug('Principal not found. Redirecting to login');
            return this.redirect && this.redirect(this.loginPath);
        }

        req.username =
            principal.getName() && principal.getName() !== 'undefined'
                ? principal.getName()
                : this.user;
        req.user = {
            userDomain: this.userDomain + '.' + req.username,
            login: req.username,
        };
        req.session.shortId = req.username;
    }

    req.authHeader = this.authHeader;

    this.success && this.success();
};

/**
 * Register a function used to configure the strategy.
 * not being used
 *
 * @api public
 * @param identifier
 * @param done
 */
Strategy.prototype.configure = function (identifier, done) {
    done();
};

module.exports = Strategy;
