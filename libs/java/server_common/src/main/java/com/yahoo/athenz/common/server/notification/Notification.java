/*
 * Copyright 2019 Oath Holdings Inc.
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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Notification {

    // Denotes notification type. MEMBERSHIP_APPROVAL, MEMBERSHIP_EXPIRY etc.
    private String type;

    // Intended recipients of notification
    private Set<String> recipients;

    // key value pair describing additional details about notification
    private Map<String, String> details;

    public Notification (String type, Set<String> recipients, Map<String, String> details) {
        this.type = type;
        this.recipients = recipients;
        this.details = details;
    }

    public Notification (String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public Set<String> getRecipients() {
        return recipients;
    }

    public Notification setRecipients(Set<String> recipients) {
        this.recipients = recipients;
        return this;
    }

    public Map<String, String> getDetails() {
        return details;
    }

    public Notification setDetails(Map<String, String> details) {
        this.details = details;
        return this;
    }

    public Notification addDetails(String name, String value) {
        if (details == null) {
            details = new HashMap<>();
        }
        details.put(name, value);
        return this;
    }

    public Notification addRecipient(String recipient) {
        if (recipients == null) {
            recipients = new HashSet<>();
        }
        recipients.add(recipient);
        return this;
    }

    @Override
    public String toString() {
        return "Notification{" +
                "type='" + type + '\'' +
                ", recipients=" + recipients +
                ", details=" + details +
                '}';
    }
}
