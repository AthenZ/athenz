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
package com.yahoo.athenz.common.server.ssh;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class SSHCertRecordTest {

    @Test
    public void testSSHCertRecord() {
        
        SSHCertRecord certRecord = new SSHCertRecord();

        certRecord.setService("cn");
        certRecord.setInstanceId("instance-id");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.1.1.1");
        certRecord.setPrivateIP("10.1.1.2");

        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getInstanceId(), "instance-id");
        assertEquals(certRecord.getPrincipals(), "host1,host2");
        assertEquals(certRecord.getClientIP(), "10.1.1.1");
        assertEquals(certRecord.getPrivateIP(), "10.1.1.2");
    }
}
