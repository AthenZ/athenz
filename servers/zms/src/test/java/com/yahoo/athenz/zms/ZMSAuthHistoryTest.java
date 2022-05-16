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
    public void testGetAuthHistoryList() {
        AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "empty.domain");
        assertEquals(authHistoryList.getAuthHistoryList(), new ArrayList<>());
        authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), 1000);
        for (int i = 0; i < 1000; ++i) {
            AuthHistory authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(i);
            assertEquals(authHistoryList.getAuthHistoryList().get(i), authHistory);
        }
    }

    @Test
    public void testGetAuthHistoryListInvalidTimestamp() {
        AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "invalid.tiestamp.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), 2);

        // Record with good timestamp
        AuthHistory authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(0);
        assertEquals(authHistoryList.getAuthHistoryList().get(0), authHistory);

        // Record with invalid timestamp
        authHistory = MockAuthHistoryStoreFactory.generateRecordForTest(1);
        authHistory.setTimestamp(null);
        assertEquals(authHistoryList.getAuthHistoryList().get(1), authHistory);
    }

    @Test
    public void testGetAuthHistoryListDisabled() {
        System.clearProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_STORE_FACTORY_CLASS);
        ZMSImpl zms = zmsTestInitializer.zmsInit();

        AuthHistoryList authHistoryList = zms.getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "some.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), 0);
    }
}
