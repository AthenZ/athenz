/*
 *
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
 *
 */

package com.yahoo.athenz.common.messaging;

import com.yahoo.athenz.common.messaging.impl.NoOpDomainChangePublisher;
import com.yahoo.athenz.common.messaging.impl.NoOpDomainChangePublisherFactory;
import org.testng.annotations.Test;

import java.time.Instant;
import java.util.UUID;

import static org.testng.Assert.assertTrue;

public class NoOpDomainChangeMessagePublisherTest {
    
    
    @Test
    public void testNoOpDomainChangePublisher() {
        ChangePublisherFactory<DomainChangeMessage> factory = new NoOpDomainChangePublisherFactory();
        ChangePublisher<DomainChangeMessage> noOpPublisher = factory.create(null, "topic");
        assertTrue(noOpPublisher instanceof NoOpDomainChangePublisher);
        DomainChangeMessage domainChangeMessage = new DomainChangeMessage();
        domainChangeMessage.setDomainName("someDomain")
            .setPublished(Instant.now().toEpochMilli())
            .setMessageId(UUID.randomUUID().toString())
            .setObjectName("group-obj")
            .setObjectType(DomainChangeMessage.ObjectType.POLICY)
            .setApiName("putGroup");
        noOpPublisher.publish(domainChangeMessage);
    }
}
