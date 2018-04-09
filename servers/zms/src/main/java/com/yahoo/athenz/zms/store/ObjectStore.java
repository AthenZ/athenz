/*
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
package com.yahoo.athenz.zms.store;

public interface ObjectStore {

    /**
     * Get a new connection from the object store with the specified
     * auto commit state and read-only/write mode
     * @param autoCommit connection will only used to make a single change
     * so auto commit option should be set thus not requiring any explicit
     * commit operations.
     * @param readWrite the request is only for a read/write operation
     * @return ObjectStoreConnection object
     */
    ObjectStoreConnection getConnection(boolean autoCommit, boolean readWrite);
    
    /**
     * Set the operation timeout for all requests
     * @param opTimeout timeout in seconds
     */
    void setOperationTimeout(int opTimeout);
    
    /**
     * Clear all connections to the object store. This is called when
     * the server tries to write some object to the object store yet
     * the store reports that it's not in write-only mode thus indicating
     * it failed over to another master. So we need to clear all our
     * connections and start new ones.
     */
    void clearConnections();
}
