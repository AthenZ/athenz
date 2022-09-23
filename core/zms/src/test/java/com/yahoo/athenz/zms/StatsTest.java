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

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class StatsTest {

    @Test
    public void testStatsObject() {
        
        Schema schema = ZMSSchema.instance();
        Validator validator = new Validator(schema);

        Stats stats = new Stats().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18)
                .setGroup(19).setGroupMember(20);

        Validator.Result result = validator.validate(stats, "Stats");
        assertTrue(result.valid);

        assertEquals(stats.getName(), "athenz");
        assertEquals(stats.getAssertion(), 10);
        assertEquals(stats.getEntity(), 11);
        assertEquals(stats.getPolicy(), 12);
        assertEquals(stats.getPublicKey(), 13);
        assertEquals(stats.getRole(), 14);
        assertEquals(stats.getRoleMember(), 15);
        assertEquals(stats.getService(), 16);
        assertEquals(stats.getServiceHost(), 17);
        assertEquals(stats.getSubdomain(), 18);
        assertEquals(stats.getGroup(), 19);
        assertEquals(stats.getGroupMember(), 20);

        Stats stats2 = new Stats().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18)
                .setGroup(19).setGroupMember(20);

        assertEquals(stats, stats2);
        assertEquals(stats, stats);

        stats2.setPublicKey(101);
        assertNotEquals(stats, stats2);
        stats2.setPublicKey(13);
        assertEquals(stats, stats2);

        stats2.setServiceHost(101);
        assertNotEquals(stats, stats2);
        stats2.setServiceHost(17);
        assertEquals(stats, stats2);

        stats2.setService(103);
        assertNotEquals(stats, stats2);
        stats2.setService(16);
        assertEquals(stats, stats2);

        stats2.setEntity(103);
        assertNotEquals(stats, stats2);
        stats2.setEntity(11);
        assertEquals(stats, stats2);

        stats2.setAssertion(103);
        assertNotEquals(stats, stats2);
        stats2.setAssertion(10);
        assertEquals(stats, stats2);

        stats2.setPolicy(101);
        assertNotEquals(stats, stats2);
        stats2.setPolicy(12);
        assertEquals(stats, stats2);

        stats2.setRoleMember(103);
        assertNotEquals(stats, stats2);
        stats2.setRoleMember(15);
        assertEquals(stats, stats2);

        stats2.setRole(102);
        assertNotEquals(stats, stats2);
        stats2.setRole(14);
        assertEquals(stats, stats2);

        stats2.setSubdomain(102);
        assertNotEquals(stats, stats2);
        stats2.setSubdomain(18);
        assertEquals(stats, stats2);

        stats2.setGroup(102);
        assertNotEquals(stats, stats2);
        stats2.setGroup(19);
        assertEquals(stats, stats2);

        stats2.setGroupMember(102);
        assertNotEquals(stats, stats2);
        stats2.setGroupMember(20);
        assertEquals(stats, stats2);

        stats2.setName(null);
        assertNotEquals(stats, stats2);
        stats2.setName("name2");
        assertNotEquals(stats, stats2);

        assertNotEquals(stats2, null);
        assertNotEquals("", stats2);
    }
}
