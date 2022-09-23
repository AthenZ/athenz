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

const fs = jest.genMockFromModule('fs');

let mockFiles = Object.create(null);
function __setMockFiles(newMockFiles) {
    mockFiles = new Map();
    for (const file in newMockFiles) {
        mockFiles.set(file, newMockFiles[file]);
    }
}

function readFileSync(fileName, options) {
    return mockFiles.get(fileName);
}

function readFile(fileName, cb) {
    if (mockFiles.get(fileName)) {
        return cb(null, mockFiles.get(fileName));
    } else {
        return cb({status: 404}, null);
    }

}

function existsSync(fileName) {
    return fileName != null;
}

function statSync(fileName) {
    return {
        size: fileName.length,
    }
}

fs.__setMockFiles = __setMockFiles;
fs.readFileSync = readFileSync;
fs.readFile = readFile;
fs.existsSync = existsSync;
fs.statSync = statSync;

module.exports = fs;
