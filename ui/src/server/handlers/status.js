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
const fs = require('fs');

module.exports = function (expressApp, config) {
    expressApp.get('/akamai', (req, res) => {
        fs.access(config.akamaiPath, fs.constants.F_OK, (err) => {
            if (err) {
                return res.status(404).send();
            } else {
                return res.status(200).send('OK');
            }
        });
    });
    expressApp.get('/status', (req, res) => {
        fs.access(config.statusPath, fs.constants.F_OK, (err) => {
            if (err) {
                return res.status(404).send();
            } else {
                return res.status(200).send('OK');
            }
        });
    });
    expressApp.get('/status.html', (req, res) => {
        fs.access(config.statusPath, fs.constants.F_OK, (err) => {
            if (err) {
                return res.status(404).send();
            } else {
                return res.status(200).send('OK');
            }
        });
    });
    expressApp.get('/autherror', (req, res) => {
        return res.send(
            'Error: Auth Provider is not available currently. Please try again later.'
        );
    });
};
