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
package com.yahoo.athenz.zts.utils;

import org.testng.annotations.Test;

import static org.testng.Assert.fail;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

public class IPBlockTest {

    @Test
    public void testInvalidIPBlock() {
        
        try {
            new IPBlock("10.1.1.1");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.1%32");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.1-24");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.256/24");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.0/33");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.0/-1");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("10.1.1.0/0");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        
        try {
            new IPBlock("172.300.10.2/32");
            fail();
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    public void testIpCheck() {
        
        // subnet/netmask: 10.1.0.1/32
        // address range: 10.1.0.1
        
        IPBlock ipBlock = new IPBlock("10.1.0.1/32");
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.1")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.2")));
        
        // subnet/netmask: 10.1.0.0/21
        // address range: 10.1.0.0 - 10.1.7.255
        
        ipBlock = new IPBlock("10.1.0.0/21");
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.0")));
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.7.255")));
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.3.25")));
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.24")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.8.0")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.0.0.0")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.2.0.0")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.2.1.255")));

        ipBlock = new IPBlock("35.160.0.0/13");
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("35.166.98.147")));
    }
    
    @Test
    public void testIpCheckWithSpaces() {
        
        // subnet/netmask: 10.1.0.1/32
        // address range: 10.1.0.1
        
        IPBlock ipBlock = new IPBlock("10.1.0.1 / 32 ");
        assertTrue(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.1")));
        assertFalse(ipBlock.ipCheck(IPBlock.convertIPToLong("10.1.0.2")));
    }
    
    @Test
    public void testIpCheckInvalidIPs() {
        
        IPBlock ipBlock = new IPBlock("10.3.0.1/32");
        try {
            ipBlock.ipCheck(IPBlock.convertIPToLong("10.1987.0.1"));
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        try {
            ipBlock.ipCheck(IPBlock.convertIPToLong("10.0.0.256"));
            fail();
        } catch (IllegalArgumentException ignored) {
        }
    }
}
