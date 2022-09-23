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

package com.yahoo.athenz.zts;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.*;

import static org.testng.Assert.*;

public class RoleCertificateRequestTest {

    @Test
    public void testRoleCertificateRequest() {

        RoleCertificateRequest data1 = new RoleCertificateRequest();
        data1.setCsr("csr1");
        data1.setProxyForPrincipal("proxy");
        data1.setPrevCertNotBefore(Timestamp.fromMillis(100));
        data1.setPrevCertNotAfter(Timestamp.fromMillis(100));
        data1.setExpiryTime(200);

        RoleCertificateRequest data2 = new RoleCertificateRequest();
        data2.setCsr("csr1");
        data2.setProxyForPrincipal("proxy");
        data2.setPrevCertNotBefore(Timestamp.fromMillis(100));
        data2.setPrevCertNotAfter(Timestamp.fromMillis(100));
        data2.setExpiryTime(200);

        assertEquals(data1, data1);
        assertEquals(data1, data2);

        // verify getters
        assertEquals("csr1", data2.getCsr());
        assertEquals(200, data2.getExpiryTime());
        assertEquals(Timestamp.fromMillis(100), data2.getPrevCertNotAfter());
        assertEquals(Timestamp.fromMillis(100), data2.getPrevCertNotBefore());
        assertEquals("proxy", data2.getProxyForPrincipal());

        data2.setExpiryTime(101);
        assertNotEquals(data1, data2);
        data2.setExpiryTime(200);

        data2.setCsr("csr2");
        assertNotEquals(data1, data2);
        data2.setCsr(null);
        assertNotEquals(data1, data2);
        data2.setCsr("csr1");

        data2.setProxyForPrincipal("proxy1");
        assertNotEquals(data1, data2);
        data2.setProxyForPrincipal(null);
        assertNotEquals(data1, data2);
        data2.setProxyForPrincipal("proxy");

        data2.setPrevCertNotBefore(Timestamp.fromMillis(101));
        assertNotEquals(data1, data2);
        data2.setPrevCertNotBefore(null);
        assertNotEquals(data1, data2);
        data2.setPrevCertNotBefore(Timestamp.fromMillis(100));

        data2.setPrevCertNotAfter(Timestamp.fromMillis(101));
        assertNotEquals(data1, data2);
        data2.setPrevCertNotAfter(null);
        assertNotEquals(data1, data2);
        data2.setPrevCertNotAfter(Timestamp.fromMillis(100));

        assertNotEquals(data1, null);
        assertNotEquals("data", data2);
    }
}
