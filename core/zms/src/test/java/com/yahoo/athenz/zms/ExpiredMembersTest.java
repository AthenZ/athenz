package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class ExpiredMembersTest {
    @Test
    public void testExpiredMembers() {

        ExpiredMembers expiredMembers1 = new ExpiredMembers();
        expiredMembers1.setExpiredGroupMembers(List.of("user.joe", "user.dan"));
        expiredMembers1.setExpiredRoleMembers(List.of("user.joe", "user.dan"));

        ExpiredMembers expiredMembers2 = new ExpiredMembers();
        expiredMembers2.setExpiredGroupMembers(List.of("user.joe", "user.dan"));
        expiredMembers2.setExpiredRoleMembers(List.of("user.joe", "user.dan"));

        assertEquals(expiredMembers1, expiredMembers2);
        assertEquals(expiredMembers1, expiredMembers1);
        assertNotEquals(null, expiredMembers2);
        assertNotEquals("expiredMembers", expiredMembers2);

        //getters
        assertEquals(expiredMembers1.getExpiredGroupMembers(), List.of("user.joe", "user.dan"));
        assertEquals(expiredMembers1.getExpiredRoleMembers(), List.of("user.joe", "user.dan"));

        assertEquals(expiredMembers2.getExpiredGroupMembers(), List.of("user.joe", "user.dan"));
        assertEquals(expiredMembers2.getExpiredRoleMembers(), List.of("user.joe", "user.dan"));

        expiredMembers2.setExpiredRoleMembers(List.of("user.avi", "user.messi"));
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(null);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(List.of("user.joe", "user.dan"));
        assertEquals(expiredMembers1, expiredMembers1);

        expiredMembers2.setExpiredGroupMembers(List.of("user.avi", "user.messi"));
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredRoleMembers(null);
        assertNotEquals(expiredMembers1, expiredMembers2);
        expiredMembers2.setExpiredGroupMembers(List.of("user.joe", "user.dan"));
        assertEquals(expiredMembers1, expiredMembers1);
    }
}
