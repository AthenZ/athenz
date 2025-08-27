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
package com.yahoo.athenz.zms.assertion;

import com.yahoo.athenz.zms.ResourceAccess;
import com.yahoo.athenz.zms.ResourceAccessList;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertTrue;

public class GcpAssumeRoleResourceUpdaterTest {

    @Test
    public void testEmptyNullCloudMap() {
        testEmptyCloudMap(null);
        testEmptyCloudMap(Collections.emptyMap());
    }

    void testEmptyCloudMap(Map<String, String> cloudMap) {
        GcpAssumeRoleResourceUpdater updater = new GcpAssumeRoleResourceUpdater();
        ResourceAccessList resourceAccessList = new ResourceAccessList();
        List<ResourceAccess> resourceList = new ArrayList<>();
        resourceList.add(new ResourceAccess());
        resourceAccessList.setResources(resourceList);
        updater.updateResourceValue(resourceAccessList, cloudMap, null);
        assertTrue(resourceAccessList.getResources().isEmpty());
    }
}
