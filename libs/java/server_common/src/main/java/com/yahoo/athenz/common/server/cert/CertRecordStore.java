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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ServerResourceException;

import java.security.cert.X509Certificate;

public interface CertRecordStore {

    /**
     * Get a new connection to the certificate record store. In case
     * of failure, a ResourceException is thrown.
     * @return CertRecordStoreConnection object
     */
    CertRecordStoreConnection getConnection() throws ServerResourceException;
    
    /**
     * Set the operation timeout in seconds
     * @param opTimeout timeout in seconds
     */
    void setOperationTimeout(int opTimeout);
    
    /**
     * Clear all connections to the cert record store
     */
    void clearConnections();

    /**
     * Log the certificate details. This method will be
     * called for all certificates issued by ZTS Server
     * regardless or not it is checked against cert
     * record details.
     * @param principal Principal who requested the certificate
     *     for initial register requests this will be null
     * @param ip IP address of the request
     * @param provider service responsible for attestation of csr
     * @param instanceId instance id if the certificate request
     *     is for a service as opposed to a role
     * @param x509Cert issued certificate
     */
    void log(final Principal principal, final String ip, final String provider,
             final String instanceId, final X509Certificate x509Cert);

    /**
     * Enable notifications to be sent regarding the store health (by supported implementers)
     * All arguments must be provided (non-null)
     * @param notificationManager notification manager
     * @param rolesProvider provider for role members
     * @param serverName name of the server
     * @return true if notifications were enabled successfully
     */
    boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider, final String serverName);
}
