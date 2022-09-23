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
const { v4: uuid } = require('uuid');
const debug = require('debug')('AthenzUI:server:handlers:logger');

module.exports = function (expressApp, config) {
    expressApp.use((req, res, next) => {
        req.headers.rid = uuid();
        res.on('finish', () => {
            req.connection.lastBytesWritten = req.connection.bytesWritten;
            if (req.body && req.body.requests) {
                Object.values(req.body.requests).forEach((call) => {
                    debug(
                        `principal: ${req.session.shortId} rid: ${
                            req.headers.rid
                        } API call: ${JSON.stringify(call)}`
                    );
                });
            }
        });
        next();
    });
};
