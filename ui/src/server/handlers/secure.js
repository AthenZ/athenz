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
// from https://github.com/zeit/next.js/blob/canary/examples/with-strict-csp/csp.js
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const cookieSession = require('cookie-session');
const csrf = require('csurf');
const multer = require('multer');

module.exports = function (expressApp, config, secrets) {
    expressApp.use((req, res, next) => {
        const scriptSrc = [`'self'`];
        const connectSrc = [`'self'`];
        // locally allow 'unsafe-inline', so HMR doesn't trigger the CSP
        if (process.env.NODE_ENV !== 'production') {
            scriptSrc.push(`'unsafe-inline'`);
            scriptSrc.push(`'unsafe-eval'`);
        } else {
            scriptSrc.push(`'nonce-${req.headers.rid}'`);
        }
        // to be used by local ZMS for ntoken based auth
        if (config.env === 'local') {
            connectSrc.push(config.zmsConnectSrcUrl);
        }
        let contentSecurityPolicy = {
            directives: {
                baseUri: [`'none'`],
                imgSrc: [`'self'`],
                scriptSrc,
                connectSrc,
                fontSrc: [`'self'`],
                frameSrc: [`'self'`],
                manifestSrc: [`'self'`],
                mediaSrc: [`'self'`],
                objectSrc: [`'self'`],
                workerSrc: [`'self'`],
                formAction: [`'self'`],
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src
                // we have set all the directives which defaultSrc sets for us, and we let nextjs set up style-src for us
                defaultSrc:
                    helmet.contentSecurityPolicy.dangerouslyDisableDefaultSrc,
            },
            useDefaults: false,
        };
        if (config.cspImgSrc && config.cspImgSrc.length !== 0) {
            contentSecurityPolicy.directives.imgSrc.push(...config.cspImgSrc);
        }
        if (config.cspReportUri && config.cspReportUri !== '') {
            contentSecurityPolicy.directives.reportUri = config.cspReportUri;
        }
        if (config.formAction && config.formAction.length !== 0) {
            contentSecurityPolicy.directives.formAction.push(
                ...config.formAction
            );
        }
        helmet({
            contentSecurityPolicy: contentSecurityPolicy,
            crossOriginEmbedderPolicy: false,
        })(req, res, next);
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
    expressApp.use(function (err, req, res, next) {
        if (err.code !== 'EBADCSRFTOKEN') {
            return next(err);
        }
        let error = new Error();
        error.message = 'Failed Input validation. Please refresh the page';
        return res.status(403).send(error);
    });
    expressApp.use(
        helmet.referrerPolicy({
            policy: 'strict-origin-when-cross-origin',
        })
    );
};
