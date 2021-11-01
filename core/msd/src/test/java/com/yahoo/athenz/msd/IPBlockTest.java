/*
 *  Copyright The Athenz Authors
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

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class IPBlockTest {
    @Test
    public void testIPBlockFields() {
        IPBlock ipBlock1 = new IPBlock().setCidr("10.0.0.1/16");
        IPBlock ipBlock2 = new IPBlock().setCidr("10.0.0.1/16");

        assertEquals(ipBlock1, ipBlock2);
        assertEquals(ipBlock1, ipBlock1);
        assertNotEquals(ipBlock1, "abc");
        assertFalse(ipBlock1.equals("abc"));

        assertEquals(ipBlock1.getCidr(), "10.0.0.1/16");

        ipBlock2.setCidr("10.1.0.1/16");
        assertNotEquals(ipBlock1, ipBlock2);
    }
}