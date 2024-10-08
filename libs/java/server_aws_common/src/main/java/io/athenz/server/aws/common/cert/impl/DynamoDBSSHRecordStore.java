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
package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.utils.X509CertUtils;
import io.athenz.server.aws.common.notification.impl.ZTSClientNotificationSenderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class DynamoDBSSHRecordStore implements SSHRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBSSHRecordStore.class);
    private static final Logger SSHLOGGER = LoggerFactory.getLogger("SSHCertLogger");

    private final DynamoDbClient dynamoDB;
    private final String tableName;
    private final ZTSClientNotificationSenderImpl ztsClientNotificationSender;

    public DynamoDBSSHRecordStore(DynamoDbClient client, final String tableName,
            ZTSClientNotificationSenderImpl ztsClientNotificationSender) {
        this.dynamoDB = client;
        this.tableName = tableName;
        this.ztsClientNotificationSender = ztsClientNotificationSender;
    }

    @Override
    public SSHRecordStoreConnection getConnection() {
        return new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }
    
    @Override
    public void clearConnections() {
    }

    @Override
    public void log(final Principal principal, final String ip, final String service,
            final String instanceId) {
        X509CertUtils.logSSH(SSHLOGGER, principal, ip, service, instanceId);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider,
            final String serverName) {
        if (ztsClientNotificationSender != null) {
            return ztsClientNotificationSender.init(notificationManager, rolesProvider, serverName);
        } else {
            LOGGER.warn("Can't enable notifications as ZTSClientNotificationSenderImpl wasn't provided in CTOR");
            return false;
        }
    }
}
