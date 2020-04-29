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
// from https://github.com/zeit/next.js/blob/canary/examples/with-strict-csp/csp.js
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const cookieSession = require('cookie-session');
const csrf = require('csurf');
const multer = require('multer');

module.exports = function(expressApp, config, secrets) {
    expressApp.use((req, res, next) => {
        const scriptSrc = [`'self'`];
        // locally allow 'unsafe-inline', so HMR doesn't trigger the CSP
        if (config.env === 'local') {
            scriptSrc.push(`'unsafe-inline'`);
        } else {
            scriptSrc.push(`'nonce-${req.headers.rid}'`);
        }
        let cspOptions = {
            contentSecurityPolicy: {
                directives: {
                    baseUri: [`'none'`],
                    imgSrc: [`'self'`],
                    // next.js sets up style-src for us
                    scriptSrc,
                },
            },
        };
        if (config.cspImgSrc && config.cspImgSrc !== '') {
            cspOptions.contentSecurityPolicy.directives.imgSrc.push(
                config.cspImgSrc
            );
        }
        if (config.cspReportUri && config.cspReportUri !== '') {
            cspOptions.contentSecurityPolicy.directives.reportUri =
                config.cspReportUri;
        }
        helmet(cspOptions)(req, res, next);
    });

    // helmet disables the X-Powered-By response header, but next.js adds it again
    expressApp.use((req, res, next) => {
        res.on('httpHooks:pre:writeHead', () => {
            res.removeHeader('X-Powered-By');
        });
        next();
    });

    expressApp.use(cookieParser());

    expressApp.use(multer().none());

    expressApp.use(
        cookieSession({
            name: 'session',
            secret: secrets.cookieSession,
            maxAge: 30 * 60 * 1000, // 30 minutes
            httpOnly: true,
            secure: true,
        })
    );

    expressApp.use(csrf());

    expressApp.use(function(err, req, res, next) {
        if (err.code !== 'EBADCSRFTOKEN') {
            return next(err);
        }
        let error = new Error();
        error.message = 'Failed Input validation. Please refresh the page';
        return res.status(403).send(error);
    });
};
