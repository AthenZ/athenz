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

package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class InfoTest {

    @Test
    public void testStatus() {

        Info info1 = new Info();
        info1.setBuildJdkSpec("17");
        info1.setImplementationTitle("athenz");
        info1.setImplementationVendor("Athenz");
        info1.setImplementationVersion("1.11.0");

        Info info2 = new Info();
        info2.setBuildJdkSpec("17");
        info2.setImplementationTitle("athenz");
        info2.setImplementationVendor("Athenz");
        info2.setImplementationVersion("1.11.0");

        assertEquals(info1, info1);
        assertEquals(info1, info2);

        // verify getters
        assertEquals("17", info1.getBuildJdkSpec());
        assertEquals("athenz", info1.getImplementationTitle());
        assertEquals("Athenz", info1.getImplementationVendor());
        assertEquals("1.11.0", info1.getImplementationVersion());

        info1.setBuildJdkSpec("11");
        assertNotEquals(info1, info2);
        info1.setBuildJdkSpec(null);
        assertNotEquals(info1, info2);
        info1.setBuildJdkSpec("17");
        assertEquals(info1, info2);

        info1.setImplementationTitle("syncer");
        assertNotEquals(info1, info2);
        info1.setImplementationTitle(null);
        assertNotEquals(info1, info2);
        info1.setImplementationTitle("athenz");
        assertEquals(info1, info2);

        info1.setImplementationVendor("vendor");
        assertNotEquals(info1, info2);
        info1.setImplementationVendor(null);
        assertNotEquals(info1, info2);
        info1.setImplementationVendor("Athenz");
        assertEquals(info1, info2);

        info1.setImplementationVersion("1.12.0");
        assertNotEquals(info1, info2);
        info1.setImplementationVersion(null);
        assertNotEquals(info1, info2);
        info1.setImplementationVersion("1.11.0");
        assertEquals(info1, info2);

        assertNotEquals(info1, null);
        assertNotEquals("data", info2);
    }
}
