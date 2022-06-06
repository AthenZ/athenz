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
package com.yahoo.athenz.zms.store;

import com.yahoo.athenz.zms.AuthHistoryDependencies;
import java.io.Closeable;

public interface AuthHistoryStoreConnection extends Closeable {

    /**
     * Close the connection to the authentication history store
     */
    void close();
    
    /**
     * Set the timeout for the authentication history record operation
     * @param opTimeout operation timeout in seconds
     */
    void setOperationTimeout(int opTimeout);

    /**
     * Retrieve the authentication history records for the given domain
     * @return the authentication history records
     */
    AuthHistoryDependencies getAuthHistory(String domain);
}
