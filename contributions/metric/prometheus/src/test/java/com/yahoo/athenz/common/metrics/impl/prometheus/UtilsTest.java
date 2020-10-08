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

import org.junit.Assert;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static com.yahoo.athenz.common.metrics.impl.prometheus.Utils.ATTRIBUTES_KEYS;
import static com.yahoo.athenz.common.metrics.impl.prometheus.Utils.ATTRIBUTES_VALUES;
import static org.testng.AssertJUnit.assertEquals;

public class UtilsTest {

    @Test
    public void testFlatArrayToMap() {
        Utils utils = new Utils();
        String[] attributes = new String[] {
                "expiry_days", "25",
                "member", "member_name",
                "notif_type", "some_notif_type",
                "reason", "some_reason",
                "unknown_key", "invalid_value"
        };

        Map<String, String[]> attributesMap = utils.flatArrayToMap(attributes);

        assertEquals(2, attributesMap.size());

        String[] expectedKeys = Utils.MetricNotificationEnum.keys();
        String[] expectedValues = new String[] {
                "some_notif_type", "", "", "", "25", "", "", "", "", "", "", "member_name", "", "some_reason", ""};
        Assert.assertArrayEquals(expectedKeys, attributesMap.get(ATTRIBUTES_KEYS));
        Assert.assertArrayEquals(expectedValues, attributesMap.get(ATTRIBUTES_VALUES));
    }

    @Test
    public void testFlatArrayToMapFailure() {

        Map<String, String[]> expectedAttributesMap = new HashMap<>();
        expectedAttributesMap.put(ATTRIBUTES_KEYS, new String[] {});
        expectedAttributesMap.put(ATTRIBUTES_VALUES, new String[] {});

        Utils utils = new Utils();

        // Check attributes with odd number of properties
        String[] oddAttributes = new String[] {
                "key1", "value1",
                "key3"
        };

        Map<String, String[]> attributesMap = utils.flatArrayToMap(oddAttributes);

        // Check null attributes
        attributesMap = utils.flatArrayToMap(null);
        assertEquals(expectedAttributesMap.size(), attributesMap.size());
        Assert.assertArrayEquals(expectedAttributesMap.get(0), attributesMap.get(0));
        Assert.assertArrayEquals(expectedAttributesMap.get(1), attributesMap.get(1));

        // Check empty attributes
        attributesMap = utils.flatArrayToMap(new String[]{});
        assertEquals(expectedAttributesMap.size(), attributesMap.size());
        Assert.assertArrayEquals(expectedAttributesMap.get(0), attributesMap.get(0));
        Assert.assertArrayEquals(expectedAttributesMap.get(1), attributesMap.get(1));    }
}
