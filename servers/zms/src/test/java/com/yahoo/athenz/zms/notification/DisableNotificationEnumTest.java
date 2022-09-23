/*
 *
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.yahoo.athenz.zms.notification;

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.EnumSet;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class DisableNotificationEnumTest {

    @Test
    public void testEnum() {
        // None disabled
        long mask = 0;
        EnumSet<DisableNotificationEnum> enumSet = DisableNotificationEnum.getEnumSet(mask);
        assertTrue(enumSet.isEmpty());

        // User disabled
        mask = 1;
        enumSet = DisableNotificationEnum.getEnumSet(mask);
        assertEquals(enumSet.size(), 1);
        assertTrue(enumSet.contains(DisableNotificationEnum.USER));

        // Admin disabled
        mask = 2;
        enumSet = DisableNotificationEnum.getEnumSet(mask);
        assertEquals(enumSet.size(), 1);
        assertTrue(enumSet.contains(DisableNotificationEnum.ADMIN));

        // Both disabled
        mask = 3;
        enumSet = DisableNotificationEnum.getEnumSet(mask);
        assertEquals(enumSet.size(), 2);
        assertTrue(enumSet.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN, DisableNotificationEnum.USER)));
    }
}
