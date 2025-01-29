/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.notification.slack;

import java.util.Objects;
import java.util.Set;

public class SlackNotification {
    private final String blocks;
    private final Set<String> fullyQualifiedRecipients;

    public SlackNotification(String blocks, Set<String> fullyQualifiedRecipients) {
        this.blocks = blocks;
        this.fullyQualifiedRecipients = fullyQualifiedRecipients;
    }

    public String getBlocks() {
        return blocks;
    }

    public Set<String> getFullyQualifiedRecipients() {
        return fullyQualifiedRecipients;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        com.yahoo.athenz.common.notification.slack.SlackNotification that = (com.yahoo.athenz.common.notification.slack.SlackNotification) o;
        return  Objects.equals(getBlocks(), that.getBlocks()) &&
                Objects.equals(getFullyQualifiedRecipients(), that.getFullyQualifiedRecipients());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getBlocks(), getFullyQualifiedRecipients());
    }
}
