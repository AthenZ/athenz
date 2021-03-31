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
import org.testng.annotations.Test;

import java.io.File;

import static org.testng.Assert.assertTrue;

public class FileWorkloadRecordStoreFactoryTest {
    @Test
    public void testCreate() {

        String tempDirPath = System.getProperty("java.io.tmpdir");
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_FILE_STORE_PATH, tempDirPath);
        System.setProperty(ZTSConsts.ZTS_PROP_WORKLOAD_FILE_STORE_NAME, "workloads-store-unittests");
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        FileWorkloadRecordStoreFactory factory = new FileWorkloadRecordStoreFactory();
        WorkloadRecordStore store = factory.create(keyStore);
        assertTrue(store instanceof FileWorkloadRecordStore);
        new File(tempDirPath + "/" + "workloads-store-unittests").delete();
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_FILE_STORE_PATH);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_FILE_STORE_NAME);
    }
}