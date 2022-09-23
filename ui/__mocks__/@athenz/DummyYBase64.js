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

class DummyYBase64 {
    static ybase64Encode(input) {
        let buffer = Buffer.isBuffer(input) ? input : new Buffer(input);
        let encoded = buffer.toString('base64');
        return encoded
            .replace(/\+/g, '.')
            .replace(/\//g, '_')
            .replace(/=/g, '-');
    }

    static ybase64Decode(input) {
        if ('string' !== typeof input) {
            throw new Error(input + ' is not string');
        }
        let encoded = input
            .replace(/\./g, '+')
            .replace(/_/g, '/')
            .replace(/-/g, '=');
        return new Buffer(encoded, 'base64');
    }
}

module.exports = DummyYBase64;
