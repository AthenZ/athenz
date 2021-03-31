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
package com.yahoo.athenz.common.server.workload;

import java.io.Closeable;
import java.util.List;

public interface WorkloadRecordStoreConnection extends Closeable {

    /**
     * Close the connection to the workload record store
     */
    void close();

    /**
     * Set the timeout for the workload record store operation
     * @param opTimeout operation timeout in seconds
     */
    void setOperationTimeout(int opTimeout);

    /**
     * Retrieve the workload record for the given instance
     * @param domain name of the domain
     * @param service name of the service
     * @return WorkloadRecord object or null if not found
     */
    List<WorkloadRecord> getWorkloadRecordsByService(String domain, String service);

    /**
     * Retrieve the workload record for the given instance
     * @param ip ip address of the workload
     * @return WorkloadRecord object or null if not found
     */
    List<WorkloadRecord> getWorkloadRecordsByIp(String ip);

    /**
     * Update the specified workload record in the store
     * @param workloadRecord WorkloadRecord to be updated
     * @return true on success otherwise false
     */
    boolean updateWorkloadRecord(WorkloadRecord workloadRecord);

    /**
     * Insert a new workload record in the store
     * @param workloadRecord WorkloadRecord to be created
     * @return true on success otherwise false
     */
    boolean insertWorkloadRecord(WorkloadRecord workloadRecord);
}
