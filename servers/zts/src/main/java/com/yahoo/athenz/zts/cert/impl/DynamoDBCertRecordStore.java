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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

public class DynamoDBCertRecordStore implements CertRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBCertRecordStore.class);
    private static final Logger CERTLOGGER = LoggerFactory.getLogger("X509CertLogger");

    private final String tableName;
    private final String currentTimeIndexName;
    private final String hostIndexName;
    private final DynamoDB dynamoDB;
    private final ZTSClientNotificationSenderImpl ztsClientNotificationSender;

    public DynamoDBCertRecordStore(AmazonDynamoDB client, final String tableName, final String currentTimeIndexName, String hostIndexName, ZTSClientNotificationSenderImpl ztsClientNotificationSender) {
        this.dynamoDB = new DynamoDB(client);
        this.tableName = tableName;
        this.currentTimeIndexName = currentTimeIndexName;
        this.hostIndexName = hostIndexName;
        this.ztsClientNotificationSender = ztsClientNotificationSender;
    }

    @Override
    public CertRecordStoreConnection getConnection() {
        try {
            return new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostIndexName);
        } catch (Exception ex) {
            LOGGER.error("getConnection: {}", ex.getMessage());
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, ex.getMessage());
        }
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }
    
    @Override
    public void clearConnections() {
    }

    @Override
    public void log(final Principal principal, final String ip, final String provider,
                    final String instanceId, final X509Certificate x509Cert) {
        X509CertUtils.logCert(CERTLOGGER, principal, ip, provider, instanceId, x509Cert);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider, final String serverName) {
        if (ztsClientNotificationSender != null) {
            return ztsClientNotificationSender.init(notificationManager, rolesProvider, serverName);
        } else {
            LOGGER.warn("Can't enable notifications as ZTSClientNotificationSenderImpl wasn't provided in CTOR");
            return false;
        }
    }
}
