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
package com.yahoo.athenz.zts.pkey;

import java.security.PrivateKey;

public interface PrivateKeyStore {

    /**
     * Retrieve private key for this ZTS Server instance to sign its tokens
     * The private key identifier must be updated in the privateKeyId out
     * StringBuilder field. The Private Key Store Factory has the knowledge
     * which hostname we're processing this request for.
     * @param privateKeyId - out argument - must be updated to include key id
     * @return private key for this ZTS Server instance.
     */
    default PrivateKey getHostPrivateKey(StringBuilder privateKeyId) {
        return null;
    }
    
    default PrivateKey getPrivateKey(String keyName, int keyVersion) {
        return null;
    }
    
    default String getPublicKey(String keyName, int keyVersion) {
        return null;
    }
}
