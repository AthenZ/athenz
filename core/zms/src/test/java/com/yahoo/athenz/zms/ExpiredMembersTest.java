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

package com.yahoo.athenz.zms;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class ExpiredMembersTest {
    @Test
    public void testExpiredMembers() {

        Timestamp expiration = Timestamp.fromCurrentTime();
        List <ExpiryMember> expiredMembers = new ArrayList<>();
        expiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.joe").setExpiration(expiration));
        expiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.dan").setExpiration(expiration));
        ExpiredMembers expiredMembers1 = new ExpiredMembers();
        expiredMembers1.setExpiredGroupMembers(expiredMembers);
        expiredMembers1.setExpiredRoleMembers(expiredMembers);

        ExpiredMembers expiredMembers2 = new ExpiredMembers();
        expiredMembers2.setExpiredGroupMembers(expiredMembers);
        expiredMembers2.setExpiredRoleMembers(expiredMembers);

        assertEquals(expiredMembers1, expiredMembers2);
        assertEquals(expiredMembers1, expiredMembers1);
        assertNotEquals(null, expiredMembers2);
        assertNotEquals("expiredMembers", expiredMembers2);

        //getters
        List <ExpiryMember> expectedExpiredMembers = new ArrayList<>();
        expectedExpiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.joe").setExpiration(expiration));
        expectedExpiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.dan").setExpiration(expiration));

        assertEquals(expiredMembers1.getExpiredGroupMembers(), expectedExpiredMembers);
        assertEquals(expiredMembers1.getExpiredRoleMembers(), expectedExpiredMembers);

        assertEquals(expiredMembers2.getExpiredGroupMembers(), expectedExpiredMembers);
        assertEquals(expiredMembers2.getExpiredRoleMembers(),expectedExpiredMembers);

        //setters
        List <ExpiryMember> newExpiredMembers = new ArrayList<>();
        newExpiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.avi").setExpiration(expiration));
        newExpiredMembers.add(new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.avi").setExpiration(expiration));

        expiredMembers2.setExpiredRoleMembers(newExpiredMembers);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(null);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(expiredMembers);
        assertEquals(expiredMembers1, expiredMembers1);

        expiredMembers2.setExpiredGroupMembers(newExpiredMembers);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(null);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredGroupMembers(expiredMembers);
        assertEquals(expiredMembers1, expiredMembers1);
    }
}
