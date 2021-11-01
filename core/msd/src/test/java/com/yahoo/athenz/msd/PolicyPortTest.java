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

public class PolicyPortTest {
    @Test
    public void testFields() {
        PolicyPort tpp1 = new PolicyPort().setPort(1024).setEndPort(65535);
        assertEquals(tpp1.getPort(), 1024);
        assertEquals(tpp1.getEndPort(), 65535);

        PolicyPort tpp2 = new PolicyPort().setPort(1024).setEndPort(65535);
        assertEquals(tpp1, tpp2);

        assertEquals(tpp1, tpp1);

        tpp2.setPort(1030);
        assertNotEquals(tpp2, tpp1);

        tpp2.setPort(1024);
        tpp2.setEndPort(10000);
        assertNotEquals(tpp2, tpp1);

        assertFalse(tpp1.equals("xyz"));
    }
}