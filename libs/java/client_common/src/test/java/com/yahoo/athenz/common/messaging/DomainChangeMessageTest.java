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

public class DomainChangeMessageTest {

    @Test
    public void testDomainChange() {
        
        DomainChangeMessage domainChange = new DomainChangeMessage();
        domainChange.setDomainName("domain")
            .setPublished(123L)
            .setMessageId("messageId")
            .setObjectName("role-obj")
            .setObjectType(DomainChangeMessage.ObjectType.ROLE)
            .setApiName("putRole");
        
        assertEquals(domainChange.getDomainName(), "domain");
        assertEquals(domainChange.getPublished(), 123L);
        assertEquals(domainChange.getMessageId(), "messageId");
        assertEquals(domainChange.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(domainChange.getObjectName(), "role-obj");
        assertEquals(domainChange.getApiName(), "putRole");
        assertEquals(domainChange, domainChange);
        
        assertFalse(domainChange.equals(null));
        assertFalse(domainChange.equals("nonDomainChange"));

        DomainChangeMessage domainChange1 = new DomainChangeMessage();
        domainChange1.setDomainName("domain")
            .setPublished(123L)
            .setMessageId("messageId")
            .setObjectName("role-obj")
            .setObjectType(DomainChangeMessage.ObjectType.ROLE)
            .setApiName("putRole");
        
        assertEquals(domainChange, domainChange1);
        assertEquals(domainChange.hashCode(), domainChange1.hashCode());

        domainChange1.setObjectType(DomainChangeMessage.ObjectType.POLICY);
        assertNotEquals(domainChange, domainChange1);
    }
    
}