/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store;

import com.yahoo.athenz.auth.PrivateKeyStore;
import java.security.PrivateKey;

public interface ChangeLogStoreFactory {

    /**
     * Set the private key store object for the changelog factory
     * in case the implementation needs to read any secrets. This
     * method is called first before the create method call.
     * @param privateKeyStore Private Key Store object
     */
    default void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
    }

    /**
     * Create and return a new ChangeLogStore instance
     * @param ztsHomeDir the home directory for the ZTS Server instance (e.g. /home/athenz/var/zts_server)
     * @param privateKey the PrivateKey to generate service tokens when communicating with ZMS Server
     * @param privateKeyId the private key identifier
     * @return ChangeLogStore instance
     */
    ChangeLogStore create(String ztsHomeDir, PrivateKey privateKey, String privateKeyId);
}
