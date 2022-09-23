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
package com.yahoo.athenz.common.server.cert;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Date;

import org.testng.annotations.Test;

public class X509CertRecordTest {

    @Test
    public void testX509CertRecord() {
        
        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();
        
        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);
        certRecord.setClientCert(true);
        certRecord.setHostName("host");
        certRecord.setLastNotifiedServer("server");
        certRecord.setLastNotifiedTime(now);
        certRecord.setExpiryTime(now);
        certRecord.setSvcDataUpdateTime(now);

        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getProvider(), "ostk");
        assertEquals(certRecord.getCurrentIP(), "current-ip");
        assertEquals(certRecord.getCurrentSerial(), "current-serial");
        assertEquals(certRecord.getCurrentTime(), now);
        assertEquals(certRecord.getInstanceId(), "instance-id");
        assertEquals(certRecord.getPrevIP(), "prev-ip");
        assertEquals(certRecord.getPrevSerial(), "prev-serial");
        assertEquals(certRecord.getPrevTime(), now);
        assertTrue(certRecord.getClientCert());
        assertEquals(certRecord.getExpiryTime(), now);
        assertEquals(certRecord.getLastNotifiedTime(), now);
        assertEquals(certRecord.getLastNotifiedServer(), "server");
        assertEquals(certRecord.getHostName(), "host");
        assertEquals(certRecord.getSvcDataUpdateTime(), now);

        final String certStr = "X509CertRecord{provider='ostk', instanceId='instance-id', service='cn', " +
                "currentSerial='current-serial', currentTime=" + now + ", currentIP='current-ip', " +
                "prevSerial='prev-serial', prevTime=" + now  + ", prevIP='prev-ip', clientCert=true, " +
                "lastNotifiedTime=" + now + ", lastNotifiedServer='server', expiryTime=" + now + ", " +
                "hostName='host', svcDataUpdateTime=" + now + "}";
        assertEquals(certRecord.toString(), certStr);
    }
}
