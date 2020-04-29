/*
 * Copyright 2020 Verizon Media
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
process.chdir(__dirname);
const https = require('https');
const express = require('express');
const next = require('next');
const appConfig = require('./src/config/config')();
const secrets = require('./src/server/secrets');
const appRoutes = require('./src/routes');
const handlers = {
    api: require('./src/server/handlers/api'),
    passportAuth: require('./src/server/handlers/passportAuth'),
    body: require('./src/server/handlers/body'),
    logger: require('./src/server/handlers/logger'),
    routes: require('./src/server/handlers/routes'),
    secure: require('./src/server/handlers/secure'),
    status: require('./src/server/handlers/status'),
};
const dev = process.env.NODE_ENV !== 'production';
const nextApp = next({ dev });
const debug = require('debug')('AthenzUI:server:app');

Promise.all([nextApp.prepare(), secrets.load(appConfig)])
    .then(() => handlers.api.load(appConfig, secrets))
    .then(
        () => {
            const expressApp = express();

            handlers.status(expressApp, appConfig);
            handlers.body(expressApp);
            handlers.logger(expressApp, appConfig);
            handlers.secure(expressApp, appConfig, secrets);
            handlers.passportAuth.auth(expressApp, appConfig, secrets);
            handlers.routes.route(expressApp, appConfig, secrets);
            expressApp.use(appRoutes.getRequestHandler(nextApp));

            const server = https.createServer(
                {
                    cert: secrets.serverCert,
                    key: secrets.serverKey,
                },
                expressApp
            );
            server.listen(appConfig.port, (err) => {
                if (err) {
                    throw err;
                }
                debug(
                    `> [Startup] Ready on https://localhost:${
                        server.address().port
                    }/`
                );
                debug('[Startup] Config used by server: %o', appConfig);
            });
        },
        (err) => {
            debug('[Startup] Fatal Error: %o', err);
            process.exit(1);
        }
    );
