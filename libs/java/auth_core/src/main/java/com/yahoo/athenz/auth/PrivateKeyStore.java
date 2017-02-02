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
package com.yahoo.athenz.auth;

import java.security.PrivateKey;

public interface PrivateKeyStore {

    /**
     * Retrieve private key for this Athenz Server instance to sign its tokens
     * The private key identifier must be updated in the privateKeyId out
     * StringBuilder field.
     * @param service Athenz service (zms or zts) requesting private key
     * @param serverHostName hostname of the Athenz Server instance
     * @param privateKeyId - out argument - must be updated to include key id
     * @return private key for this ZMS Server instance.
     */
    default PrivateKey getPrivateKey(String service, String serverHostName,
            StringBuilder privateKeyId) {
        return null;
    }
}
