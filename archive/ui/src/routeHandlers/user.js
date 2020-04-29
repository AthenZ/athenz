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

const fs = require('fs');
const crypto = require('crypto');

module.exports = {
  signToken: function(token, authKey, version) {
    var data = token + ';bk=' + version;
    var pk = crypto.createSign('sha256');
    pk.update(data);
    var sig = pk.sign(authKey, 'base64', 'base64');

    // This is to put the 'y' in 'ybase64'
    sig = sig.replace(/\+/g, '.');
    sig = sig.replace(/\//g, '_');
    sig = sig.replace(/=/g, '-');

    var result = data + ';bs=' + sig;
    return result;
  }
};
