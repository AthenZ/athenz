/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer.auth.history;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.syncer_common.SyncTimeRange;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.*;

public class AuthHistorySyncerTest {

    @Test
    public void testSyncFailClassNotSpecified() {
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        long startTime = 1650271929000L; // 18/Apr/2022:08:52:09
        long endTime = 1650444729000L; // 20/Apr/2022:08:52:09
        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        assertFalse(authHistorySyncer.sync(syncTimeRange));
    }

    @Test
    public void testSyncEmpty() {
        System.setProperty("auth_history_syncer.fetch_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistoryFetcherFactory");
        System.setProperty("auth_history_syncer.send_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistorySenderFactory");
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        long startTime = 1650271929000L; // 18/Apr/2022:08:52:09
        long endTime = 1650444729000L; // 20/Apr/2022:08:52:09
        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        assertTrue(authHistorySyncer.sync(syncTimeRange));
        System.clearProperty("auth_history_syncer.fetch_factory_class");
        System.clearProperty("auth_history_syncer.send_factory_class");
    }

    @Test
    public void testSyncPushFailed() {
        System.setProperty("auth_history_syncer.fetch_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistoryFetcherFactory");
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        Long startTime = 1650185529000L; // 17/Apr/2022:08:52:09
        Long endTime = 1650271929000L; // 18/Apr/2022:08:52:09
        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        assertFalse(authHistorySyncer.sync(syncTimeRange));
        System.clearProperty("auth_history_syncer.fetch_factory_class");
    }

    @Test
    public void testSyncFailPush() {
        System.setProperty("auth_history_syncer.fetch_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistoryFetcherFactory");
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        Long startTime = 1650185529000L; // 17/Apr/2022:08:52:09
        Long endTime = 1650271929000L; // 18/Apr/2022:08:52:09
        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        assertFalse(authHistorySyncer.sync(syncTimeRange));
        System.clearProperty("auth_history_syncer.fetch_factory_class");
    }

    @Test
    public void testSync() {
        System.setProperty("auth_history_syncer.fetch_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistoryFetcherFactory");
        System.setProperty("auth_history_syncer.send_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockAuthHistorySenderFactory");
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        Long startTime = 1650185529000L; // 17/Apr/2022:08:52:09
        Long endTime = 1650271929000L; // 18/Apr/2022:08:52:09
        SyncTimeRange syncTimeRange = new SyncTimeRange(startTime, endTime);
        assertTrue(authHistorySyncer.sync(syncTimeRange));
        System.clearProperty("auth_history_syncer.fetch_factory_class");
        System.clearProperty("auth_history_syncer.send_factory_class");
    }

    @Test
    public void testGetPrivateKeyStore() {
        System.setProperty("auth_history_syncer.private_key_store_factory_class", "com.yahoo.athenz.syncer.auth.history.impl.MockPrivateKeyStoreFactory");
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        PrivateKeyStore privateKeyStore = authHistorySyncer.getPrivateKeyStore();
        assertNotNull(privateKeyStore);
        System.clearProperty("auth_history_syncer.private_key_store_factory_class");
    }

    @Test
    public void testAuthHistorySyncerFailures() {
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        assertNotNull(authHistorySyncer);
        AuthHistorySyncer.usage();

        System.setProperty("auth_history_syncer.fetch_factory_class", "unknown-class");
        try {
            authHistorySyncer.getAuthHistoryFetcher(null, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof ClassNotFoundException);
        }

        System.setProperty("auth_history_syncer.private_key_store_factory_class", "unknown-class");
        try {
            authHistorySyncer.getPrivateKeyStore();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid private key store"));
        }

        System.setProperty("auth_history_syncer.send_factory_class", "unknown-class");
        try {
            authHistorySyncer.getAuthHistorySender(null, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof ClassNotFoundException);
        }

        System.clearProperty("auth_history_syncer.fetch_factory_class");
        System.clearProperty("auth_history_syncer.send_factory_class");
        System.clearProperty("auth_history_syncer.private_key_store_factory_class");
    }
}
