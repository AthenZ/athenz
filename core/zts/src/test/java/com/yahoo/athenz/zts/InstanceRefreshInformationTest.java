/**
 * Copyright 2017 Yahoo Inc.
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.Test;

public class InstanceRefreshInformationTest {

    @Test
    public void testInstanceRefreshInformation() {
        InstanceRefreshInformation i = new InstanceRefreshInformation();
        InstanceRefreshInformation i2 = new InstanceRefreshInformation();

        // set
        i.setCsr("sample_csr");
        i.setSsh("ssh");
        i.setToken(false);
        i2.setCsr("sample_csr");
        i2.setSsh("ssh");
        i2.setToken(false);

        // getter assertion
        assertEquals(i.getCsr(), "sample_csr");
        assertEquals(i.getSsh(), "ssh");
        assertEquals(i.getToken(), Boolean.FALSE);
        
        assertTrue(i.equals(i2));
        
        i2.setCsr("sample_csr2");
        assertFalse(i2.equals(i));
        i2.setCsr(null);
        assertFalse(i2.equals(i));
    }
}
