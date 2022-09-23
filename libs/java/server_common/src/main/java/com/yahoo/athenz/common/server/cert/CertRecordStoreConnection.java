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
package com.yahoo.athenz.common.server.cert;

import java.io.Closeable;
import java.util.List;

public interface CertRecordStoreConnection extends Closeable {

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
     * Retrieve the certificate record for the given instance
     * @param provider name of the provider
     * @param instanceId instance id
     * @param service name of the service
     * @return X509CertRecord object or null if not found
     */
    X509CertRecord getX509CertRecord(String provider, String instanceId, String service);
    
    /**
     * Update the specified certificate record in the store
     * @param certRecord X509CertRecord to be updated
     * @return true on success otherwise false
     */
    boolean updateX509CertRecord(X509CertRecord certRecord);
    
    /**
     * Insert a new certificate record in the store
     * @param certRecord X509CertRecord to be created
     * @return true on success otherwise false
     */
    boolean insertX509CertRecord(X509CertRecord certRecord);
    
    /**
     * Delete the certificate record for the given instance
     * @param provider name of the provider
     * @param instanceId instance id
     * @param service name of the service
     * @return true on success otherwise false
     */
    boolean deleteX509CertRecord(String provider, String instanceId, String service);

    /**
     * Delete all expired x509 certificate records. A certificate is
     * considered expired if it hasn't been updated within the
     * specified number of minutes
     * @param expiryTimeMins expiry time in minutes
     * @return number of records deleted
     */
    int deleteExpiredX509CertRecords(int expiryTimeMins);

    /**
     * Return all certificate records that failed to refresh after updating them with the current notification time and server.
     * Implementers of this interface should note the following:
     * 1. The records should be filtered according to the following criteria:
     *      - The certificates should have a grace period in which no notifications will be sent. The default grace period is 2 weeks
     *      - Provider as specified in the provider argument
     *      - Hadn't been notified in the last 24 hours
     *      - Filter outdated records from rebootstrapped hosts (if several records share the same host / provider / service but not the same instanceId, only leave the records with the latest "currentTime")
     * 2. Update all records matching the criteria with the "lastNotifiedTime" and "lastNotifiedServer".
     * You can look at JDBCCertRecordStoreConnection and DynamoDBCertRecordStoreConnection for example implementations of JDBC and DynamoDB respectively
     * @param lastNotifiedServer - Name of athenz server
     * @param lastNotifiedTime last nofitification time
     * @param provider name of the provider
     * @return List of certificates that failed to refresh
     */
    List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(String lastNotifiedServer,
                                                                            long lastNotifiedTime,
                                                                            String provider);
}
