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
package com.yahoo.athenz.auth;

public interface AuthorityKeyStore {

    /**
     * Set the key store to be used by the authority. This object
     * is expected to be used by the authority to retrieve public
     * keys for the given service identities in pem format
     * @param keyStore KeyStore object
     */
    void setKeyStore(KeyStore keyStore);
}
