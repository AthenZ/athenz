/**
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

var fs = require('fs');
var config = require('../config/config.js')();
var auth_core = require('@athenz/auth-core');
var YBase64 = auth_core.YBase64;
var KeyStore = auth_core.KeyStore;

class PublicKeyStore extends KeyStore {
  static getPublicKey(domain, service, keyId) {
    if (!domain || !service || !keyId) {
      return null;
    }

    switch (domain + '.' + service) {
      case 'sys.auth.zms':
        var publicKeys = JSON.parse(fs.readFileSync(process.cwd() + '/config/athenz.conf')).zmsPublicKeys;
        for (var id in publicKeys) {
          if (publicKeys[id].id === keyId) {
            return YBase64.ybase64Decode(publicKeys[id].key);
          }
        }
        return null;
      case config.serviceFQN:
        return fs.readFileSync('keys/' + config.serviceFQN + '_pub.pem');
      default:
        return null;
    }
  }
}

module.exports = PublicKeyStore;
