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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class TransportRuleTest {
    @Test
    public void testTransportRuleFields() {
        TransportRule tr1 = new TransportRule();
        tr1.setEndPoint("10.20.30.40/26").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535").setDirection(TransportDirection.IN);
        assertNotNull(tr1);
        assertEquals(tr1.getEndPoint(), "10.20.30.40/26");
        assertEquals(tr1.getPort(), 4443);
        assertEquals(tr1.getProtocol(), "TCP");
        assertEquals(tr1.getSourcePortRange(), "1024-65535");
        assertEquals(tr1.getDirection(), TransportDirection.IN);
        assertEquals(tr1, tr1);

        TransportRule tr2 = new TransportRule();
        tr2.setEndPoint("10.20.30.40/26").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535").setDirection(TransportDirection.IN);

        assertEquals(tr1, tr2);

        tr2.setEndPoint("20.20.30.40/26");
        assertNotEquals(tr1, tr2);
        tr2.setEndPoint(null);
        assertNotEquals(tr1, tr2);

        tr2.setEndPoint("10.20.30.40/26");
        tr2.setPort(8443);
        assertNotEquals(tr1, tr2);

        tr2.setPort(4443);
        tr2.setProtocol("UDP");
        assertNotEquals(tr1, tr2);
        tr2.setProtocol(null);
        assertNotEquals(tr1, tr2);

        tr2.setProtocol("TCP");
        tr2.setSourcePortRange("49152-65535");
        assertNotEquals(tr1, tr2);
        tr2.setSourcePortRange(null);
        assertNotEquals(tr1, tr2);

        tr2.setSourcePortRange("1024-65535");
        tr2.setDirection(TransportDirection.OUT);
        assertNotEquals(tr1, tr2);

        tr2.setDirection(null);
        assertNotEquals(tr1, tr2);
        tr2.setDirection(TransportDirection.IN);
        assertEquals(tr1, tr2);

        assertNotEquals(tr1, null);
        // for code coverage
        assertFalse(tr1.equals("mystring"));
        assertNotEquals(tr1, "mystring");

        assertEquals(tr1, tr1);

    }
}