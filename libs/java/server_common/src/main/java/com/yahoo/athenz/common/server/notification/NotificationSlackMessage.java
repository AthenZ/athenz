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

package com.yahoo.athenz.common.server.notification;

import java.util.Objects;
import java.util.Set;

public class NotificationSlackMessage {

    private final String message;
    private final Set<String> recepients;

    public NotificationSlackMessage(String message, Set<String> recepients) {
        this.recepients = recepients;
        this.message = message;
    }

    public String getMessage() {
        return message;
    }


    public Set<String> getRecipients() {
        return recepients;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        NotificationSlackMessage that = (NotificationSlackMessage) o;
        return  Objects.equals(getMessage(), that.getMessage()) &&
                Objects.equals(getRecipients(), that.getRecipients());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getMessage(), getRecipients());
    }
}
