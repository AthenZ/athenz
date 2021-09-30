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

package com.yahoo.athenz.common.messaging;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class PolicyChangeMessageTest {

    @Test
    public void testDomainChange() {

        PolicyChangeMessage policyChangeMessage = new PolicyChangeMessage()
                .setDomainName("athenz.examples")
                .setPolicyName("writers")
                .setMessageId("uuid123")
                .setPublished(123L);

        assertEquals(policyChangeMessage.getDomainName(), "athenz.examples");
        assertEquals(policyChangeMessage.getPolicyName(), "writers");
        assertEquals(policyChangeMessage.getMessageId(), "uuid123");
        assertEquals(policyChangeMessage.getPublished(), 123L);

        assertEquals(policyChangeMessage, policyChangeMessage);

        assertFalse(policyChangeMessage.equals(null));
        assertFalse(policyChangeMessage.equals("nonPolicyChange"));

        PolicyChangeMessage policyChangeMessage1 = new PolicyChangeMessage()
                .setDomainName("athenz.examples")
                .setPolicyName("writers")
                .setMessageId("uuid123")
                .setPublished(123L);
        
        assertEquals(policyChangeMessage, policyChangeMessage1);
        assertEquals(policyChangeMessage.hashCode(), policyChangeMessage1.hashCode());

        policyChangeMessage1.setPolicyName("readers");
        assertNotEquals(policyChangeMessage, policyChangeMessage1);
    }
}
