/**
 * Copyright 2016 Yahoo Inc.
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

var ATHENZ_PROP_PRIVATE_KEY = "athenz.auth.private_key_store.private_key";
var ATHENZ_PROP_PRIVATE_KEY_ID = "athenz.auth.private_key_store.private_key_id";

const winston = require('winston');

class FilePrivateKeyStore {

  constructor() {
  }

  getPrivateKey(service, serverHostName, privateKeyId) {

    privKeyName = System.getProperty(ATHENZ_PROP_PRIVATE_KEY);

    winston.debug("FilePrivateKeyStore: private key file=" + privKeyName);

    if (privKeyName === null) {
      return null;
    }

    // check to see if this is running in dev mode and thus it's
    // a resource in our jar file

    var privKey = null;
    privKey = Crypto.ybase64Encode(fs.readFileSync(privKeyName));

    var pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
    if (pkey != null) {
      privateKeyId.append(System.getProperty(ATHENZ_PROP_PRIVATE_KEY_ID, "0"));
    }

    return pkey;
  }

  _retrieveKeyFromResource(resourceName) {

    var key = null;
    try (InputStream is = getClass().getResourceAsStream(resourceName)) {
      var resourceData = getString(is);
      if (resourceData != null) {
        key = Crypto.ybase64(resourceData.getBytes("UTF-8"));
      }
    } catch (IOException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("FilePrivateKeyStore: Unable to read key from resource: " + resourceName);
      }
    }

    return key;
  }

  _getString(is) {

    if (is == null) {
      return null;
    }

    int ch;
    StringBuilder sb = new StringBuilder();
    while ((ch = is.read()) != -1) {
      sb.append((char) ch);
    }
    return sb.toString();
  }

  _validateAuthorizeService(userToken, callback) {
    var authorizedServiceName = userToken.getAuthorizedServiceName();
    if (authorizedServiceName === null) {
      var authorizedServices = userToken.getAuthorizedServices();
      if (authorizedServices === null || authorizedServices.length != 1) {
        return null;
      } else {
        authorizedServiceName = authorizedServices[0];
      }
    }

    var idx = authorizedServiceName.lastIndexOf('.');
    if (idx <= 0 || idx == authorizedServiceName.length - 1) {
      return null;
    }

    var publicKey = keystore.getPublicKey(authorizedServiceName.substring(0, idx), authorizedServiceName.substring(idx + 1), userToken.getAuthorizedServiceKeyId());

    if (!userToken.validateForAuthorizedService(publicKey)) {
      return null;
    }
    return authorizedServiceName;
  }

  setKeyStore(keyStore) {
    this.keyStore = keyStore;
  }
}

module.exports = FilePrivateKeyStore;
