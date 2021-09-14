/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.messaging;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.time.Instant;
import java.util.UUID;

import static com.yahoo.athenz.common.messaging.DomainChangePublisherFactory.ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class NoOpDomainChangeMessagePublisherTest {

    @BeforeClass
    public void setUp() {
        System.clearProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS);
    }

    @Test
    public void invalidFactoryClass() {
        System.setProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS, "com.yahoo.athenz.zms.messaging.noexist");
        try {
            DomainChangePublisherFactory.create();
            fail();
        } catch (ExceptionInInitializerError ignored) { }
        System.clearProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS);
    }
    
    @Test
    public void testNoOpDomainChangePublisher() {
        DomainChangePublisher noOpPublisher = DomainChangePublisherFactory.create();
        assertTrue(noOpPublisher instanceof NoOpDomainChangePublisher);
        DomainChangeMessage domainChangeMessage = new DomainChangeMessage();
        domainChangeMessage.setDomainName("someDomain")
            .setPublished(Instant.now().toEpochMilli())
            .setUuid(UUID.randomUUID().toString())
            .setRoleChange(true);
        noOpPublisher.publishMessage(domainChangeMessage);
    }
}
