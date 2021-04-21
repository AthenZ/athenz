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

import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.testng.annotations.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.testng.Assert.*;

public class FileWorkloadRecordStoreConnectionTest {
    @Test
    public void testWorkloadOperations() {
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-workload-tests"));
        File rootDir = new File("/tmp/zts-workload-tests");
        rootDir.deleteOnExit();
        FileWorkloadRecordStore store = new FileWorkloadRecordStore(rootDir);
        FileWorkloadRecordStoreConnection con = (FileWorkloadRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        con.setOperationTimeout(10);

        // first verify that we don't have the entry
        List<WorkloadRecord> wlRecordCheck = con.getWorkloadRecordsByService("athenz","api");
        assertTrue(wlRecordCheck.isEmpty());

        WorkloadRecord workloadRecord = new WorkloadRecord();
        Date now = new Date();
        workloadRecord.setService("athenz.api");
        workloadRecord.setProvider("openstack");
        workloadRecord.setInstanceId("instance-id");
        workloadRecord.setIp("10.0.0.1");
        workloadRecord.setHostname("test-host.corp.yahoo.com");
        workloadRecord.setCreationTime(now);
        workloadRecord.setUpdateTime(now);

        boolean result = con.insertWorkloadRecord(workloadRecord);
        assertTrue(result);

        wlRecordCheck = con.getWorkloadRecordsByService("athenz", "api");
        assertNotNull(wlRecordCheck);
        assertEquals(wlRecordCheck.get(0).getProvider(), "openstack");
        assertEquals(wlRecordCheck.get(0).getInstanceId(), "instance-id");
        assertEquals(wlRecordCheck.get(0).getIp(), "10.0.0.1");
        assertEquals(wlRecordCheck.get(0).getHostname(), "test-host.corp.yahoo.com");
        assertEquals(wlRecordCheck.get(0).getCreationTime().getTime(), now.getTime());
        assertEquals(wlRecordCheck.get(0).getUpdateTime().getTime(), now.getTime());

        wlRecordCheck = con.getWorkloadRecordsByIp("10.0.0.1");
        assertNotNull(wlRecordCheck);
        assertEquals(wlRecordCheck.get(0).getProvider(), "openstack");
        assertEquals(wlRecordCheck.get(0).getInstanceId(), "instance-id");
        assertEquals(wlRecordCheck.get(0).getService(), "athenz.api");
        assertEquals(wlRecordCheck.get(0).getHostname(), "test-host.corp.yahoo.com");
        assertEquals(wlRecordCheck.get(0).getCreationTime().getTime(), now.getTime());
        assertEquals(wlRecordCheck.get(0).getUpdateTime().getTime(), now.getTime());

        workloadRecord.setProvider("kubernetes");
        result = con.updateWorkloadRecord(workloadRecord);
        assertTrue(result);

        wlRecordCheck = con.getWorkloadRecordsByIp("10.0.0.1");
        assertNotNull(wlRecordCheck);
        assertEquals(wlRecordCheck.get(0).getProvider(), "kubernetes");

        assertTrue(con.getWorkloadRecordsByService("xyz", "abc").isEmpty());
        assertTrue(con.getWorkloadRecordsByIp("172.10.0.131").isEmpty());
        assertNull(con.getWorkloadRecord(new File("/proc/root")));
        try {
            con.writeWorkloadRecord(new File("/proc/root"), "xyz");
        } catch (Exception ignored) {
            fail();
        }
        con.close();
    }
}