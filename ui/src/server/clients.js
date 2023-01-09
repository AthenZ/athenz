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
const rdlRest = require('../rdl-rest');
const CLIENTS = {};
const debug = require('debug')('AthenzUI:server:clients');
const userService = require('../server/services/userService');

const certRefreshTime = 24 * 60 * 60 * 1000; // refresh cert and key once a day
const userDataRefreshTime = 5 * 60 * 1000; // refresh user data every 5 mins

function refreshCertClients(config, options) {
    debug('refreshing clients ');

    CLIENTS.zms = rdlRest({
        apiHost: config.zms,
        rdl: require('../config/zms.json'),
        requestOpts: {
            strictSSL: config.strictSSL,
        },
    });

    CLIENTS.zts = rdlRest({
        apiHost: config.zts,
        rdl: require('../config/zts.json'),
        requestOpts: {
            strictSSL: config.strictSSL,
        },
    });

    CLIENTS.msd = rdlRest({
        apiHost: config.msd,
        rdl: require('../config/msd.json'),
        requestOpts: {
            strictSSL: config.strictSSL,
        },
    });

    CLIENTS.ums = rdlRest({
        apiHost: config.ums,
        rdl: require('../config/ums.json'),
        requestOpts: {
            strictSSL: config.strictSSL,
        },
    });

    userService.refreshUserData(config);

    return Promise.resolve();
}

function setCookieinClients(req) {
    req.cookiesForwardCheck = {};
    return {
        cookie: function (currentReq) {
            /*jshint sub: true */
            if (currentReq.cookiesForwardCheck[currentReq.currentMethod]) {
                return currentReq.headers.cookie;
            }
            return null;
        },
        [req.authHeader]: function (currentReq) {
            if (currentReq.authSvcToken) {
                return currentReq.authSvcToken;
            }
            return null;
        },
    };
}

module.exports.load = function load(config, options) {
    setInterval(() => refreshCertClients(config, options), certRefreshTime);

    setInterval(() => userService.refreshUserData(config), userDataRefreshTime);

    return refreshCertClients(config, options);
};

module.exports.middleware = function middleware() {
    return (req, res, next) => {
        req.clients = {
            zms: CLIENTS.zms(req, setCookieinClients(req)),
            msd: CLIENTS.msd(req, setCookieinClients(req)),
            zts: CLIENTS.zts(req, setCookieinClients(req)),
            ums: CLIENTS.ums(req, setCookieinClients(req)),
        };
        next();
    };
};
