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
const debug = require('debug')('AthenzUI:server:handlers:passportAuth');
const passport = require('passport');
const AuthStrategy = require('./AuthStrategy');
const authUtils = require('../utils/authUtils');

module.exports.auth = function (expressApp, config, secrets) {
    debug('[Startup] initializing passport');
    expressApp.use(passport.initialize({}));

    debug('[Startup] configuring auth strategy middleware');
    passport.use('ui-auth', new AuthStrategy(expressApp, config, secrets));

    debug('[Startup] adding auth strategy middleware');
    expressApp.use((req, res, next) => {
        passport.authenticate('ui-auth', {}, (err, data) => {
            authUtils.postAuth(req, res, config, err);
            next();
        })(req, res);
    });
};
