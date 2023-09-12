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

package com.yahoo.athenz.common.server.notification;

import java.util.Objects;
import java.util.Set;

public class NotificationEmail {
    private final String subject;
    private final String body;
    private final Set<String> fullyQualifiedRecipientsEmail;

    public NotificationEmail(String subject, String body, Set<String> fullyQualifiedRecipientsEmail) {
        this.subject = subject;
        this.body = body;
        this.fullyQualifiedRecipientsEmail = fullyQualifiedRecipientsEmail;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public Set<String> getFullyQualifiedRecipientsEmail() {
        return fullyQualifiedRecipientsEmail;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        NotificationEmail that = (NotificationEmail) o;
        return getSubject().equals(that.getSubject()) &&
                Objects.equals(getBody(), that.getBody()) &&
                Objects.equals(getFullyQualifiedRecipientsEmail(), that.getFullyQualifiedRecipientsEmail());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getSubject(), getBody(), getFullyQualifiedRecipientsEmail());
    }
}
