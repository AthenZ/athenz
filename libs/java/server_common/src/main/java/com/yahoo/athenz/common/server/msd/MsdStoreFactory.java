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

package com.yahoo.athenz.common.server.msd;

import com.yahoo.athenz.auth.PrivateKeyStore;

public interface MsdStoreFactory {

    /**
     * Create and return a new MsdStoreConnection instance. The MsdStoreConnection
     * will be responsible for write/reads for Workloads into the underlying MSD storage
     * @param keyStore private key store object for fetching any secrets if needed
     * @return MsdStoreConnection instance
     */
    MsdStore create(PrivateKeyStore keyStore);
}
