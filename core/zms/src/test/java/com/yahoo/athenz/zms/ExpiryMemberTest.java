package com.yahoo.athenz.zms;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class ExpiryMemberTest {
    @Test
    public void testExpiryMember() {
        ExpiryMember expiryMember1 = new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.joe").setExpiration(Timestamp.fromMillis(100));
        ExpiryMember expiryMember2 = new ExpiryMember().setDomainName("dom").setCollectionName("test").setPrincipalName("user.joe").setExpiration(Timestamp.fromMillis(100));

        assertEquals(expiryMember1, expiryMember2);
        assertEquals(expiryMember2, expiryMember1);
        assertNotEquals(null, expiryMember2);
        assertNotEquals("expiredMembers", expiryMember2);

        //getters
        assertEquals(expiryMember1.getDomainName(), "dom");
        assertEquals(expiryMember1.getCollectionName(), "test");
        assertEquals(expiryMember1.getPrincipalName(), "user.joe");
        assertEquals(expiryMember1.getExpiration(), Timestamp.fromMillis(100));

        assertEquals(expiryMember2.getDomainName(), "dom");
        assertEquals(expiryMember2.getCollectionName(), "test");
        assertEquals(expiryMember2.getPrincipalName(), "user.joe");
        assertEquals(expiryMember2.getExpiration(), Timestamp.fromMillis(100));

        expiryMember2.setDomainName("dom1");
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setDomainName(null);
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setDomainName("dom");
        assertEquals(expiryMember1, expiryMember2);

        //setters
        expiryMember2.setDomainName("dom1");
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setDomainName(null);
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setDomainName("dom");
        assertEquals(expiryMember1, expiryMember2);

        expiryMember2.setCollectionName("test1");
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setCollectionName(null);
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setCollectionName("test");
        assertEquals(expiryMember1, expiryMember2);

        expiryMember2.setPrincipalName("user.dan");
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setPrincipalName(null);
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setPrincipalName("user.joe");
        assertEquals(expiryMember1, expiryMember2);

        expiryMember2.setExpiration(Timestamp.fromMillis(101));
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setExpiration(null);
        assertNotEquals(expiryMember1, expiryMember2);
        expiryMember2.setExpiration(Timestamp.fromMillis(100));
        assertEquals(expiryMember1, expiryMember2);
    }
}
