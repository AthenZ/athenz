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
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import io.athenz.server.aws.common.notification.impl.ZTSClientNotificationSenderImpl;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class DynamoDBSSHRecordStoreTest {

    @Mock private DynamoDbClient dbClient;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetConnection() {

        DynamoDBSSHRecordStore store = new DynamoDBSSHRecordStore(dbClient, "Athenz-ZTS-Table", null);

        SSHRecordStoreConnection dbConn = store.getConnection();
        assertNotNull(dbConn);

        // empty methods
        store.setOperationTimeout(10);
        store.clearConnections();
    }

    @Test
    public void testLog() {

        DynamoDBSSHRecordStore store = new DynamoDBSSHRecordStore(dbClient, "Athenz-ZTS-Table", null);

        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athenz.api", "1234");
    }

    @Test
    public void testEnableNotifications() {
        DynamoDBSSHRecordStore store = new DynamoDBSSHRecordStore(dbClient, "Athenz-ZTS-Table", null);
        boolean isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        ZTSClientNotificationSenderImpl ztsClientNotificationSender = new ZTSClientNotificationSenderImpl();
        store = new DynamoDBSSHRecordStore(dbClient, "Athenz-ZTS-Table", ztsClientNotificationSender);
        isEnabled = store.enableNotifications(null, null, null);
        assertFalse(isEnabled);

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";
        isEnabled = store.enableNotifications(notificationManager, rolesProvider, serverName);
        assertTrue(isEnabled);
    }
}
