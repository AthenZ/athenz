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

import java.util.Objects;

public class PolicyChangeMessage {

    // domain name in which policy has changed
    private String domainName;

    // policy name that went through a change
    private String policyName;

    // policy change message id
    private String messageId;

    // milliseconds since the epoch
    private long published;

    public String getDomainName() {
        return domainName;
    }

    public PolicyChangeMessage setDomainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    public String getPolicyName() {
        return policyName;
    }

    public PolicyChangeMessage setPolicyName(String policyName) {
        this.policyName = policyName;
        return this;
    }

    public String getMessageId() {
        return messageId;
    }

    public PolicyChangeMessage setMessageId(String messageId) {
        this.messageId = messageId;
        return this;
    }

    public long getPublished() {
        return published;
    }

    public PolicyChangeMessage setPublished(long published) {
        this.published = published;
        return this;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PolicyChangeMessage that = (PolicyChangeMessage) o;
        return domainName.equals(that.domainName) &&
                policyName.equals(that.policyName) &&
                messageId.equals(that.messageId) &&
                published == that.published ;
    }

    @Override
    public int hashCode() {
        return Objects.hash(domainName, policyName, messageId, published);
    }
}
