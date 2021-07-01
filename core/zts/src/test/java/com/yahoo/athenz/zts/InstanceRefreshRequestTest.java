/*
 * Copyright 2016 Yahoo Inc.
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

import static org.testng.Assert.*;

@SuppressWarnings("EqualsWithItself")
public class InstanceRefreshRequestTest {

    @Test
    public void testInstanceRefreshRequest() {
        InstanceRefreshRequest i1 = new InstanceRefreshRequest();
        i1.setCsr("test_csr");
        i1.setExpiryTime(123456789);
        i1.setKeyId("v0");

        InstanceRefreshRequest i2 = new InstanceRefreshRequest();
        i2.setCsr("test_csr");
        i2.setExpiryTime(123456789);
        i2.setKeyId("v0");

        // getter
        assertEquals(i1.getCsr(), "test_csr");
        assertEquals(i1.getExpiryTime(), (Integer) 123456789);
        assertEquals(i1.getKeyId(), "v0");

        assertEquals(i1, i1);
        assertEquals(i2, i1);

        i2.setCsr("csr2");
        assertNotEquals(i1, i2);
        i2.setCsr(null);
        assertNotEquals(i1, i2);
        i2.setCsr("test_csr");

        i2.setKeyId("keyid2");
        assertNotEquals(i1, i2);
        i2.setKeyId(null);
        assertNotEquals(i1, i2);
        i2.setKeyId("v0");

        i2.setExpiryTime(100);
        assertNotEquals(i1, i2);
        i2.setExpiryTime(null);
        assertNotEquals(i1, i2);
        i2.setExpiryTime(123456789);

        assertNotEquals("data", i1);
    }

}
