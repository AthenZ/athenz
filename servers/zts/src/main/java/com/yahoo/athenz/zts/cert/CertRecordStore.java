/*
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.zts.cert;

public interface CertRecordStore {

    /**
     * Get a new connection to the certificate record store. In case
     * of failure, a ResourceException is thrown.
     * @return CertRecordStoreConnection object
     */
    CertRecordStoreConnection getConnection();
    
    /**
     * Set the operation timeout in seconds
     * @param opTimeout timeout in seconds
     */
    void setOperationTimeout(int opTimeout);
    
    /**
     * Clear all connections to the cert record store
     */
    void clearConnections();
}
