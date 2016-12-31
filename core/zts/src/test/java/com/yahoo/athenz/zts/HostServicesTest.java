/**
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

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

public class HostServicesTest {

    @Test
    public void testHostService() {
        HostServices hs = new HostServices();
        HostServices hs2 = new HostServices();

        List<String> nl = new ArrayList<String>();
        nl.add("sample.service1");

        // set
        hs.setNames(nl);
        hs.setHost("sample.com");
        hs2.setHost("sample.com");

        // getter assertion
        assertEquals(hs.getHost(), "sample.com");
        assertEquals(hs.getNames(), nl);
        assertTrue(hs.equals(hs));
        
        assertFalse(hs2.equals(hs));
        hs2.setHost(null);
        assertFalse(hs2.equals(hs));
        
        assertFalse(hs.equals(new String()));

    }
}
