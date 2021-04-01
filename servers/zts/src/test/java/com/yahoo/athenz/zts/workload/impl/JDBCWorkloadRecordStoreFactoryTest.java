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

package com.yahoo.athenz.zts.workload.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.zts.ZTSConsts;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

public class JDBCWorkloadRecordStoreFactoryTest {

    @Test
    public void testCreate() {

        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_JDBC_STORE, "jdbc:mysql://localhost");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_JDBC_USER, "user");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_JDBC_PASSWORD, "password");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.doReturn("password").when(keyStore).getApplicationSecret("jdbc", "password");

        JDBCWorkloadRecordStoreFactory factory = new JDBCWorkloadRecordStoreFactory();
        WorkloadRecordStore store = factory.create(keyStore);
        Assert.assertNotNull(store);
    }
}