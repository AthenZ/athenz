/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms.store;

public interface AuthHistoryStore {
    /**
     * Get a new connection to the authentication history store. In case
     * of failure, a ResourceException is thrown.
     * @return CertRecordStoreConnection object
     */
    AuthHistoryStoreConnection getConnection();

    /**
     * Set the operation timeout in seconds
     * @param opTimeout timeout in seconds
     */
    void setOperationTimeout(int opTimeout);

    /**
     * Clear all connections to the authentication history store
     */
    void clearConnections();
}
