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
class ServiceKeyUtils {
    static y64Decode(key) {
        let b64 = key.replace(/\./g, '+').replace(/_/g, '/').replace(/-/g, '=');
        return Buffer.from(b64, 'base64').toString();
    }

    static y64Encode(key) {
        return Buffer.from(key)
            .toString('base64')
            .replace(/\+/g, '.')
            .replace(/\//g, '_')
            .replace(/=/g, '-');
    }

    static trimKey(key) {
        key = key
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/ /g, '\n');
        return '-----BEGIN PUBLIC KEY-----' + key + '-----END PUBLIC KEY-----';
    }
}

export default ServiceKeyUtils;
