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

package com.yahoo.athenz.msd;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class TransportPolicyRequestTest {

    @Test
    public void testMethods() {
        TransportPolicyRequest t1 = new TransportPolicyRequest();
        t1.setDirection(TransportPolicyTrafficDirection.INGRESS);
        t1.setIdentifier("id");
        t1.setSubject(new TransportPolicySubject().setDomainName("domain").setServiceName("service"));
        t1.setConditions(List.of(new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(List.of(TransportPolicyScope.ALL))));
        t1.setSourcePorts(List.of(new TransportPolicyPort().setPort(1024).setEndPort(65535).setProtocol(TransportPolicyProtocol.TCP)));
        t1.setDestinationPorts(List.of(new TransportPolicyPort().setPort(4443).setEndPort(4443).setProtocol(TransportPolicyProtocol.TCP)));
        t1.setPeers(List.of(new TransportPolicySubject().setDomainName("domain2").setServiceName("service2")));

        TransportPolicyRequest t2 = new TransportPolicyRequest();
        t2.setDirection(TransportPolicyTrafficDirection.INGRESS);
        t2.setIdentifier("id");
        t2.setSubject(new TransportPolicySubject().setDomainName("domain").setServiceName("service"));
        t2.setConditions(List.of(new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(List.of(TransportPolicyScope.ALL))));
        t2.setSourcePorts(List.of(new TransportPolicyPort().setPort(1024).setEndPort(65535).setProtocol(TransportPolicyProtocol.TCP)));
        t2.setDestinationPorts(List.of(new TransportPolicyPort().setPort(4443).setEndPort(4443).setProtocol(TransportPolicyProtocol.TCP)));
        t2.setPeers(List.of(new TransportPolicySubject().setDomainName("domain2").setServiceName("service2")));

        assertEquals(t1, t2);
        assertFalse(t1.equals("abc"));

        assertEquals(t1.getDirection(), TransportPolicyTrafficDirection.INGRESS);
        assertEquals(t1.getIdentifier(), "id");
        assertEquals(t1.getSubject().getDomainName(), "domain");
        assertEquals(t1.getConditions().get(0).getEnforcementState(), TransportPolicyEnforcementState.ENFORCE);
        assertEquals(t1.getSourcePorts().get(0).getPort(), 1024);
        assertEquals(t1.getDestinationPorts().get(0).getEndPort(), 4443);
        assertEquals(t1.getPeers().get(0).getServiceName(), "service2");

        t2.setDirection(TransportPolicyTrafficDirection.EGRESS);
        assertNotEquals(t1, t2);

        t2.setDirection(TransportPolicyTrafficDirection.INGRESS);
        t2.setIdentifier("id2");
        assertNotEquals(t1, t2);

        t2.setIdentifier("id");
        t2.setSubject(new TransportPolicySubject().setDomainName("domain").setServiceName("service2"));
        assertNotEquals(t1, t2);

        t2.setSubject(new TransportPolicySubject().setDomainName("domain").setServiceName("service"));
        t2.setConditions(new java.util.ArrayList<>());
        assertNotEquals(t1, t2);

        t2.setConditions(List.of(new TransportPolicyCondition().setEnforcementState(TransportPolicyEnforcementState.ENFORCE).setScope(List.of(TransportPolicyScope.ALL))));
        t2.setSourcePorts(new java.util.ArrayList<>());
        assertNotEquals(t1, t2);

        t2.setSourcePorts(List.of(new TransportPolicyPort().setPort(1024).setEndPort(65535).setProtocol(TransportPolicyProtocol.TCP)));
        t2.setDestinationPorts(new java.util.ArrayList<>());
        assertNotEquals(t1, t2);

        t2.setDestinationPorts(List.of(new TransportPolicyPort().setPort(4443).setEndPort(4443).setProtocol(TransportPolicyProtocol.TCP)));
        t2.setPeers(new java.util.ArrayList<>());
        assertNotEquals(t1, t2);
    }
}