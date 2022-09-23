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

const fs = require('fs');
const auth_core = require('@athenz/auth-core');
const YBase64 = auth_core.YBase64;
const KeyStore = auth_core.KeyStore;

const config = require('../../config/config.js')();

const debug = require('debug')('AthenzUI:server:handlers:PublicKeyStore');

class PublicKeyStore extends KeyStore {
    static getPublicKey(domain, service, keyId) {
        debug('domain: %s, service: %s, keyId: %s', domain, service, keyId);
        if (!domain || !service || !keyId) {
            return null;
        }

        switch (domain + '.' + service) {
            case 'sys.auth.zms':
                let cfgPath = process.env.UI_CONF_PATH
                    ? process.env.UI_CONF_PATH + '/athenz.conf'
                    : 'src/config/athenz.conf';
                let publicKeys = JSON.parse(
                    fs.readFileSync(cfgPath)
                ).zmsPublicKeys;
                for (var id in publicKeys) {
                    if (publicKeys[id].id === keyId) {
                        return YBase64.ybase64Decode(publicKeys[id].key);
                    }
                }
                return null;
            case config.athenzDomainService:
                return fs.readFileSync(
                    'keys/' + config.athenzDomainService + '_pub.pem'
                );
            default:
                return null;
        }
    }
}

module.exports = PublicKeyStore;
