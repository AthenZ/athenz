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

var crypto = require('crypto');
var ybase64 = require('./YBase64');

var SALT_BYTES = 4;

class Crypto {
    static hmac(message, sharedSecret) {
        try {
            var hmac = crypto.createHmac('sha256', sharedSecret);
            hmac.update(message);
            return ybase64.ybase64Encode(hmac.digest());
        } catch (e) {
            throw new Error('Crypto:hmac:' + e.message);
        }
    }

    static sign(message, key, digestAlgorithm) {
        try {
            var sign = crypto.createSign(digestAlgorithm);
            sign.update(message);
            return ybase64.ybase64Encode(sign.sign(key));
        } catch (e) {
            throw new Error('Crypto:sign:' + e.message);
        }
    }

    static verify(message, key, signature, digestAlgorithm) {
        try {
            var sig = ybase64.ybase64Decode(signature);
            var verify = crypto.createVerify(digestAlgorithm);
            verify.update(message);
            return verify.verify(key, sig);
        } catch (e) {
            throw new Error('Crypto:verify:' + e.message);
        }
    }

    static randomSalt() {
        var salt = crypto.randomBytes(SALT_BYTES);
        return salt.toString('hex');
    }
}

module.exports = Crypto;
