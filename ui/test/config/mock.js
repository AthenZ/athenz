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

var mock = require('mock-require');
var crypto = require('crypto');
var fs = require('fs');

mock('../../src/routeHandlers/user', {
  signToken: function(token, key, version) {
    var authKeyFile = process.env.AUTHKEY || process.env.HOME + '/authkey.pem';
    var authKey = fs.readFileSync(authKeyFile, 'utf8');
    var data = token + ';bk=authkey.' + version;
    if (authKey) {
      var pk = crypto.createSign('RSA-SHA256');
      pk.update(data);
      var sig = pk.sign(authKey, 'base64', 'base64');

      // This is to put the 'y' in 'ybase64'
      sig = sig.replace(/\+/g, '.');
      sig = sig.replace(/\//g, '_');
      sig = sig.replace(/=/g, '-');

      var result = data + ';bs=' + sig;

      console.log('returning with a signed token: ', result);
      return result;
    } else {
      console.error('Failed to sign user token, authKey not found');
    }
  }
});
