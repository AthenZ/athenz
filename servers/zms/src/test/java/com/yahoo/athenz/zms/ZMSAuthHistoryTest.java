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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.zms.store.MockAuthHistoryStoreFactory;
import org.testng.annotations.*;

import java.util.ArrayList;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class ZMSAuthHistoryTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_STORE_FACTORY_CLASS, "com.yahoo.athenz.zms.store.MockAuthHistoryStoreFactory");
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testGetAuthHistoryDependencies() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        AuthHistoryDependencies authHistoryDependencies = zmsImpl.getAuthHistoryDependencies(ctx, "empty.domain");
        assertEquals(authHistoryDependencies.getOutgoingDependencies(), new ArrayList<>());
        assertEquals(authHistoryDependencies.getIncomingDependencies(), new ArrayList<>());
        authHistoryDependencies = zmsImpl.getAuthHistoryDependencies(ctx, "test.domain");
        assertEquals(authHistoryDependencies.getIncomingDependencies().size(), 500);
        for (int i = 0; i < 500; ++i) {
            AuthHistory authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(i);
            assertEquals(authHistoryDependencies.getIncomingDependencies().get(i), authHistory);
        }
        assertEquals(authHistoryDependencies.getOutgoingDependencies().size(), 500);
        for (int i = 500; i < 1000; ++i) {
            AuthHistory authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(i);
            assertEquals(authHistoryDependencies.getOutgoingDependencies().get(i - 500), authHistory);
        }
    }

    @Test
    public void testGetAuthHistoryDependenciesInvalidTimestamp() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        AuthHistoryDependencies authHistoryDependencies = zmsImpl.getAuthHistoryDependencies(ctx, "invalid.timestamp.domain");
        assertEquals(authHistoryDependencies.getIncomingDependencies().size(), 2);
        assertTrue(authHistoryDependencies.getOutgoingDependencies().isEmpty());

        // Record with good timestamp
        AuthHistory authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(0);
        assertEquals(authHistoryDependencies.getIncomingDependencies().get(0), authHistory);

        // Record with invalid timestamp
        authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(1);
        authHistory.setTimestamp(null);
        assertEquals(authHistoryDependencies.getIncomingDependencies().get(1), authHistory);
    }

    @Test
    public void testGetAuthHistoryDependenciesDisabled() {
        System.clearProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_STORE_FACTORY_CLASS);
        ZMSImpl zms = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        AuthHistoryDependencies authHistoryDependencies = zms.getAuthHistoryDependencies(ctx, "some.domain");
        assertEquals(authHistoryDependencies.getIncomingDependencies().size(), 0);
        assertEquals(authHistoryDependencies.getOutgoingDependencies().size(), 0);
    }
}
