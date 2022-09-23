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
'use strict';
const debug = require('debug')('AthenzUI:server:userServiceImpl');

// Babilon doesn't allow us to require('fs') - probably because it suspects that the code might be executed in the browser.
// So this method returns the string 'fs' in a very confusing way. Babilon stands no chance...
const confuseBalilonFS = () => 'fs';
const fs = require('fs');

function checkUsersUpdate(directory, fileName) {
    return new Promise((resolve, reject) => {
        let file = directory + '/' + fileName;
        if (fs.existsSync(file)) {
            return resolve(fs.statSync(file).size);
        }
        debug('error in loading file : %s', file);
        return reject(`File ${file} does not exist`);
    });
}

function loadUpdatedFile(directory, fileName) {
    return new Promise((resolve, reject) => {
        let file = directory + '/' + fileName;
        fs.readFile(file, (err, body) => {
            if (err) {
                debug('error in loading file : %o', err);
                return reject(err);
            } else {
                return resolve(body.toString().trim());
            }
        });
    });
}

module.exports.checkUsersUpdate = checkUsersUpdate;
module.exports.fetchUpdatedUsers = loadUpdatedFile;
