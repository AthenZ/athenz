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
package com.yahoo.athenz.common.server.ssh;

import java.io.Closeable;

public interface SSHRecordStoreConnection extends Closeable {

    /**
     * Close the connection to the certificate record store
     */
    void close();
    
    /**
     * Set the timeout for the certificate record store operation
     * @param opTimeout operation timeout in seconds
     */
    void setOperationTimeout(int opTimeout);

    /**
     * Retrieve the ssh certificate record for the given instance
     * @param instanceId instance id
     * @param service name of the service
     * @return X509CertRecord object or null if not found
     */
    SSHCertRecord getSSHCertRecord(String instanceId, String service);

    /**
     * Update the specified ssh certificate record in the store
     * @param certRecord SSHCertRecord to be updated
     * @return true on success otherwise false
     */
    boolean updateSSHCertRecord(SSHCertRecord certRecord);

    /**
     * Insert a new ssh certificate record in the store
     * @param certRecord SSHCertRecord to be created
     * @return true on success otherwise false
     */
    boolean insertSSHCertRecord(SSHCertRecord certRecord);

    /**
     * Delete the ssh certificate record for the given instance
     * @param instanceId instance id
     * @param service name of the service
     * @return true on success otherwise false
     */
    boolean deleteSSHCertRecord(String instanceId, String service);

    /**
     * Delete all expired ssh certificate records. A certificate is
     * considered expired if it hasn't been updated within the
     * specified number of minutes
     * @param expiryTimeMins expiry time in minutes
     * @return number of records deleted
     */
    int deleteExpiredSSHCertRecords(int expiryTimeMins);
}
