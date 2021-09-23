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

package com.yahoo.athenz.common.messaging.impl;

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.messaging.DomainChangePublisher;

/**
 * Default and empty implementation of {@link DomainChangePublisher}
 */
public class NoOpDomainChangePublisher implements DomainChangePublisher {

    public NoOpDomainChangePublisher(String topicName) {
        
    }
    
    @Override
    public void publishMessage(DomainChangeMessage domainChangeMessage) {
        // do nothing
    }
}
