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

import com.yahoo.rdl.Timestamp;

import java.util.*;

public class Notification {

    // Intended recipients of notification
    private Set<String> recipients;

    // key value pair describing additional details about notification
    private Map<String, String> details;

    // Utility class to convert the notification into an email
    private NotificationToEmailConverter notificationToEmailConverter;

    // Utility class to convert the notification into metric attributes
    private NotificationToMetricConverter notificationToMetricConverter;

    public Notification () {
    }

    public Set<String> getRecipients() {
        if (recipients == null) {
            recipients = new HashSet<>();
        }
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

    public Notification setNotificationToEmailConverter(NotificationToEmailConverter notificationToEmailConverter) {
        this.notificationToEmailConverter = notificationToEmailConverter;
        return this;
    }

    public NotificationEmail getNotificationAsEmail() {
        if (notificationToEmailConverter != null) {
            return notificationToEmailConverter.getNotificationAsEmail(this);
        }
        return null;
    }

    public Notification setNotificationToMetricConverter(NotificationToMetricConverter notificationToMetricConverter) {
        this.notificationToMetricConverter = notificationToMetricConverter;
        return this;
    }

    public NotificationMetric getNotificationAsMetrics(Timestamp currentTime) {
        if (notificationToMetricConverter != null) {
            return notificationToMetricConverter.getNotificationAsMetrics(this, currentTime);
        }
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Notification that = (Notification) o;
        Timestamp currentTime = Timestamp.fromMillis(System.currentTimeMillis());
        return  Objects.equals(getRecipients(), that.getRecipients()) &&
                Objects.equals(getDetails(), that.getDetails()) &&
                Objects.equals(getNotificationAsMetrics(currentTime), that.getNotificationAsMetrics(currentTime)) &&
                Objects.equals(getNotificationAsEmail(), that.getNotificationAsEmail());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getRecipients(), getDetails());
    }

    @Override
    public String toString() {
        String emailConverterClassName = "";
        if (notificationToEmailConverter != null) {
            emailConverterClassName = notificationToEmailConverter.getClass().getName();
        }
        String metricConverterClassName = "";
        if (notificationToMetricConverter != null) {
            metricConverterClassName = notificationToMetricConverter.getClass().getName();
        }
        return "Notification{" +
                "recipients=" + recipients +
                ", details=" + details +
                ", emailConverterClass=" + emailConverterClassName +
                ", metricConverterClass=" + metricConverterClassName +
                '}';
    }
}
