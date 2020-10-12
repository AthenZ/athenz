/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.common.metrics.impl.prometheus;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class Utils {
    public static final String ATTRIBUTES_KEYS = "keys";
    public static final String ATTRIBUTES_VALUES = "values";

    public enum MetricNotificationEnum {
        METRIC_NOTIFICATION_TYPE_KEY            ("notif_type"),
        METRIC_NOTIFICATION_DOMAIN_KEY          ("domain"),
        METRIC_NOTIFICATION_ZTS_KEY             ("zts_url"),
        METRIC_NOTIFICATION_ROLE_KEY            ("role"),
        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY     ("expiry_days"),
        METRIC_NOTIFICATION_UPDATE_DAYS_KEY     ("update_days"),
        METRIC_NOTIFICATION_REVIEW_DAYS_KEY     ("review_days"),
        METRIC_NOTIFICATION_ZTS_HEALTH_MSG_KEY  ("zts_health_msg"),
        METRIC_NOTIFICATION_SERVICE_KEY         ("service"),
        METRIC_NOTIFICATION_PROVIDER_KEY        ("provider"),
        METRIC_NOTIFICATION_INSTANCE_ID_KEY     ("instance_id"),
        METRIC_NOTIFICATION_MEMBER_KEY          ("member"),
        METRIC_NOTIFICATION_GROUP_KEY           ("group"),
        METRIC_NOTIFICATION_REASON_KEY          ("reason"),
        METRIC_NOTIFICATION_REQUESTER_KEY       ("requester");

        public final String label;

        public static String[] keys() {
            return Stream.of(MetricNotificationEnum.values()).map(a -> a.label).toArray(String[]::new);
        }

        private MetricNotificationEnum(String label) {
            this.label = label;
        }

        private static final Map<String, MetricNotificationEnum> ENUM_MAP;
        // Build an immutable map of String name to enum pairs.
        static {
            Map<String, MetricNotificationEnum> map = new ConcurrentHashMap<String, MetricNotificationEnum>();
            for (MetricNotificationEnum instance : MetricNotificationEnum.values()) {
                map.put(instance.label, instance);
            }
            ENUM_MAP = Collections.unmodifiableMap(map);
        }

        public static MetricNotificationEnum getByName (String name) {
            return ENUM_MAP.get(name);
        }
    }

    /**
     * Convert the flat map attributes to an array of keys and array of values
     * @param attributes in the format [key1, value1, key2, value2,..., keyN, valueN]
     * @return Map in the format <"keys", [key1, key2,..., keyN]> and <"values", [value1, value2,..., valueN]>
     */
    public Map<String, String[]> flatArrayToMap(String[] attributes) {
        final String[] keys = MetricNotificationEnum.keys();
        Map<String, String[]> attributesMap = new HashMap<>();
        attributesMap.put(ATTRIBUTES_KEYS, keys);
        String[] values = new String[keys.length];
        Arrays.fill(values, "");
        attributesMap.put(ATTRIBUTES_VALUES, values);

        if (attributes == null || attributes.length == 0 || attributes.length % 2 != 0) {
            // Flat array length should be even (each key should have a value)
            return attributesMap;
        }

        for (int i = 0; i < attributes.length; i += 2) {
            MetricNotificationEnum metricNotificationEnum = MetricNotificationEnum.getByName(attributes[i]);
            if (metricNotificationEnum != null) {
                values[metricNotificationEnum.ordinal()] = attributes[i + 1];
            }
        }

        return attributesMap;
    }
}
