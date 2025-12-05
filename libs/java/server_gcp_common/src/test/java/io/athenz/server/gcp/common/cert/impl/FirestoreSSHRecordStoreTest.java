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
package io.athenz.server.gcp.common.cert.impl;

import com.google.cloud.firestore.Firestore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class FirestoreSSHRecordStoreTest {

    @Mock private Firestore firestore;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetConnection() {

        FirestoreSSHRecordStore store = new FirestoreSSHRecordStore(firestore, "test-collection");

        SSHRecordStoreConnection dbConn = store.getConnection();
        assertNotNull(dbConn);

        // empty methods
        store.setOperationTimeout(10);
        store.clearConnections();
    }

    @Test
    public void testLog() {

        FirestoreSSHRecordStore store = new FirestoreSSHRecordStore(firestore, "test-collection");

        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athenz.api", "1234");
    }

    @Test
    public void testEnableNotifications() {
        FirestoreSSHRecordStore store = new FirestoreSSHRecordStore(firestore, "test-collection");

        NotificationManager notificationManager = Mockito.mock(NotificationManager.class);
        RolesProvider rolesProvider = Mockito.mock(RolesProvider.class);
        String serverName = "testServer";

        boolean isEnabled = store.enableNotifications(notificationManager, rolesProvider, serverName);
        assertFalse(isEnabled);
    }
}
