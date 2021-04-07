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

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class TransportRulesTest {
    @Test
    public void testTransportRulesFields() {
        TransportRules trs1 = new TransportRules();

        TransportRule tr1 = new TransportRule();
        tr1.setEndPoint("10.20.30.40/26").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535");

        TransportRule tr2 = new TransportRule();
        tr2.setEndPoint("10.20.30.40/26").setPort(8443).setProtocol("TCP").setSourcePortRange("1024-65535");

        List<TransportRule> ingressTransportRules1 = Collections.singletonList(tr1);
        List<TransportRule> egressTransportRules1 = Collections.singletonList(tr2);

        trs1.setIngressRules(ingressTransportRules1);
        trs1.setEgressRules(egressTransportRules1);

        assertNotNull(trs1.getIngressRules());
        assertNotNull(trs1.getEgressRules());

        TransportRules trs2 = new TransportRules();

        TransportRule tr21 = new TransportRule();
        tr21.setEndPoint("10.20.30.40/26").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535");

        TransportRule tr22 = new TransportRule();
        tr22.setEndPoint("10.20.30.40/26").setPort(8443).setProtocol("TCP").setSourcePortRange("1024-65535");

        List<TransportRule> ingressTransportRules2 = Collections.singletonList(tr21);
        List<TransportRule> egressTransportRules2 = Collections.singletonList(tr22);

        trs2.setIngressRules(ingressTransportRules2);
        trs2.setEgressRules(egressTransportRules2);

        assertNotNull(trs2.getIngressRules());
        assertNotNull(trs2.getEgressRules());

        trs2.setIngressRules(ingressTransportRules1);
        trs2.setEgressRules(egressTransportRules1);

        assertEquals(trs1, trs2);

        trs2.setIngressRules(null);
        assertNotEquals(trs1, trs2);

        trs2.setIngressRules(ingressTransportRules1);
        trs2.setEgressRules(null);
        assertNotEquals(trs1, trs2);
        trs2.setIngressRules(ingressTransportRules1);

        trs2 = trs1;
        assertEquals(trs1, trs2);

        // for code coverage
        assertFalse(trs1.equals("anotherstring"));

        assertNotEquals(trs1, null);
        assertNotEquals(trs1, "mystring");

    }
}