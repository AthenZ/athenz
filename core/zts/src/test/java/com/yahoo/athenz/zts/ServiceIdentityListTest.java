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

import java.util.Collections;

import org.testng.annotations.Test;

import static org.testng.Assert.*;
import static org.testng.Assert.assertNotEquals;

public class ServiceIdentityListTest {

    @Test
    public void testServiceIdentityList() {
        ServiceIdentityList sil1 = new ServiceIdentityList();
        ServiceIdentityList sil2 = new ServiceIdentityList();

        sil1.setNames(Collections.singletonList("principal1"));
        sil2.setNames(Collections.singletonList("principal1"));

        assertEquals(Collections.singletonList("principal1"), sil1.getNames());

        assertEquals(sil1, sil2);
        assertEquals(sil1, sil1);

        sil1.setNames(Collections.singletonList("principal2"));
        assertNotEquals(sil2, sil1);
        sil1.setNames(null);
        assertNotEquals(sil2, sil1);
        sil1.setNames(Collections.singletonList("principal1"));
        assertEquals(sil2, sil1);

        assertNotEquals(sil2, null);
        assertNotEquals("sil1", sil1);
    }
}
