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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class ReviewTest {

    @Test
    public void testReviewObject() {

        ReviewObject object1 = new ReviewObject()
            .setDomainName("domain1").setName("name1")
            .setGroupReviewDays(10).setGroupExpiryDays(20)
            .setMemberReviewDays(30).setMemberExpiryDays(40)
            .setServiceReviewDays(50).setServiceExpiryDays(60)
            .setLastReviewedDate(Timestamp.fromMillis(123456789))
            .setCreated(Timestamp.fromMillis(123456789));

        ReviewObject object2 = new ReviewObject()
            .setDomainName("domain1").setName("name1")
            .setGroupReviewDays(10).setGroupExpiryDays(20)
            .setMemberReviewDays(30).setMemberExpiryDays(40)
            .setServiceReviewDays(50).setServiceExpiryDays(60)
            .setLastReviewedDate(Timestamp.fromMillis(123456789))
            .setCreated(Timestamp.fromMillis(123456789));

        assertEquals(object1, object1);
        assertEquals(object1, object2);
        assertNotEquals("data", object2);

        // verify getters

        assertEquals("domain1", object1.getDomainName());
        assertEquals("name1", object1.getName());
        assertEquals(10, object1.getGroupReviewDays());
        assertEquals(20, object1.getGroupExpiryDays());
        assertEquals(30, object1.getMemberReviewDays());
        assertEquals(40, object1.getMemberExpiryDays());
        assertEquals(50, object1.getServiceReviewDays());
        assertEquals(60, object1.getServiceExpiryDays());
        assertEquals(Timestamp.fromMillis(123456789), object1.getLastReviewedDate());
        assertEquals(Timestamp.fromMillis(123456789), object1.getCreated());

        object1.setDomainName("domain2");
        assertNotEquals(object1, object2);
        object1.setDomainName(null);
        assertNotEquals(object1, object2);
        object1.setDomainName("domain1");
        assertEquals(object1, object2);

        object1.setName("name2");
        assertNotEquals(object1, object2);
        object1.setName(null);
        assertNotEquals(object1, object2);
        object1.setName("name1");
        assertEquals(object1, object2);

        object1.setGroupReviewDays(11);
        assertNotEquals(object1, object2);
        object1.setGroupReviewDays(10);
        assertEquals(object1, object2);

        object1.setGroupExpiryDays(21);
        assertNotEquals(object1, object2);
        object1.setGroupExpiryDays(20);
        assertEquals(object1, object2);

        object1.setMemberReviewDays(31);
        assertNotEquals(object1, object2);
        object1.setMemberReviewDays(30);
        assertEquals(object1, object2);

        object1.setMemberExpiryDays(41);
        assertNotEquals(object1, object2);
        object1.setMemberExpiryDays(40);
        assertEquals(object1, object2);

        object1.setServiceReviewDays(51);
        assertNotEquals(object1, object2);
        object1.setServiceReviewDays(50);
        assertEquals(object1, object2);

        object1.setServiceExpiryDays(61);
        assertNotEquals(object1, object2);
        object1.setServiceExpiryDays(60);
        assertEquals(object1, object2);

        object1.setLastReviewedDate(Timestamp.fromMillis(123456780));
        assertNotEquals(object1, object2);
        object1.setLastReviewedDate(null);
        assertNotEquals(object1, object2);
        object1.setLastReviewedDate(Timestamp.fromMillis(123456789));
        assertEquals(object1, object2);

        object1.setCreated(Timestamp.fromMillis(123456780));
        assertNotEquals(object1, object2);
        object1.setCreated(null);
        assertNotEquals(object1, object2);
        object1.setCreated(Timestamp.fromMillis(123456789));
        assertEquals(object1, object2);
    }

    @Test
    public void testReviewObjects() {

        ReviewObjects objects1 = new ReviewObjects();
        ReviewObjects objects2 = new ReviewObjects();

        assertEquals(objects1, objects1);
        assertEquals(objects1, objects2);
        assertNotEquals("data", objects2);

        // verify getters

        assertNull(objects1.getList());

        ReviewObject object1 = new ReviewObject()
                .setDomainName("domain1").setName("name1");
        objects1.setList(Collections.singletonList(object1));
        assertEquals(objects1.getList().size(), 1);
        assertNotEquals(objects1, objects2);

        objects2.setList(Collections.singletonList(object1));
        assertEquals(objects1, objects2);
    }
}
