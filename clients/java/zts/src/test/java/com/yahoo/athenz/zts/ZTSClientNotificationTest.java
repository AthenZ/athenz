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
package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ZTSClientNotificationTest {

    @Test
    public void testConstructorAndGetters() {
        String ztsURL = "https://zts.example.com";
        String role = "admin";
        String type = "access_token";
        long expiration = 1234567890L;
        boolean isInvalid = false;
        String domain = "example.domain";

        ZTSClientNotification notification = new ZTSClientNotification(ztsURL, role, type, expiration, isInvalid, domain);

        assertEquals(notification.getZtsURL(), ztsURL);
        assertEquals(notification.getRole(), role);
        assertEquals(notification.getType(), type);
        assertEquals(notification.getExpiration(), expiration);
        assertEquals(notification.getIsInvalidToken(), isInvalid);
        assertEquals(notification.getDomain(), domain);
        assertEquals(notification.getMessage(), "Fail to get token of type " + type + ". ");
    }

    @Test
    public void testConstructorWithInvalidToken() {
        String ztsURL = "https://zts.example.com";
        String role = "admin";
        String type = "access_token";
        long expiration = 1234567890L;
        boolean isInvalid = true;
        String domain = "example.domain";

        ZTSClientNotification notification = new ZTSClientNotification(ztsURL, role, type, expiration, isInvalid, domain);

        assertTrue(notification.getIsInvalidToken());
        assertEquals(notification.getMessage(), 
                "Fail to get token of type " + type + ".  Will not re-attempt to fetch token as token is invalid.");
    }

    @Test
    public void testConstructorWithNullValues() {
        String ztsURL = "https://zts.example.com";
        String role = null;
        String type = null;
        long expiration = 0L;
        boolean isInvalid = false;
        String domain = null;

        ZTSClientNotification notification = new ZTSClientNotification(ztsURL, role, type, expiration, isInvalid, domain);

        assertEquals(notification.getZtsURL(), ztsURL);
        assertNull(notification.getRole());
        assertNull(notification.getType());
        assertEquals(notification.getExpiration(), 0L);
        assertFalse(notification.getIsInvalidToken());
        assertNull(notification.getDomain());
        assertEquals(notification.getMessage(), "Fail to get token of type null. ");
    }

    @Test
    public void testEqualsSameObject() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertEquals(notification, notification);
    }

    @Test
    public void testEqualsNullObject() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification, null);
    }

    @Test
    public void testEqualsDifferentClass() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification, "not a notification");
    }

    @Test
    public void testEqualsSameValues() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertEquals(notification2, notification1);
        assertEquals(notification1, notification2);
    }

    @Test
    public void testEqualsDifferentZtsURL() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts2.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsDifferentRole() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "user", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsDifferentType() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "role_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsDifferentExpiration() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 9876543210L, false, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsDifferentIsInvalidToken() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, true, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsDifferentDomain() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "other.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testEqualsWithNullRole() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", null, "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", null, "access_token", 1234567890L, false, "example.domain");

        assertEquals(notification2, notification1);
    }

    @Test
    public void testEqualsWithNullDomain() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, null);
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, null);

        assertEquals(notification2, notification1);
    }

    @Test
    public void testEqualsWithNullRoleOneSide() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", null, "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification2, notification1);
    }

    @Test
    public void testHashCodeSameValues() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");

        assertEquals(notification1.hashCode(), notification2.hashCode());
    }

    @Test
    public void testHashCodeDifferentValues() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 1234567890L, false, "example.domain");
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", "user", "access_token", 1234567890L, false, "example.domain");

        assertNotEquals(notification1.hashCode(), notification2.hashCode());
    }

    @Test
    public void testHashCodeWithNullValues() {
        ZTSClientNotification notification1 = new ZTSClientNotification(
                "https://zts.example.com", null, null, 1234567890L, false, null);
        ZTSClientNotification notification2 = new ZTSClientNotification(
                "https://zts.example.com", null, null, 1234567890L, false, null);

        assertEquals(notification1.hashCode(), notification2.hashCode());
    }

    @Test
    public void testMessageGenerationWithInvalidTokenFalse() {
        String type = "role_token";
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", type, 1234567890L, false, "example.domain");

        String expectedMessage = "Fail to get token of type " + type + ". ";
        assertEquals(notification.getMessage(), expectedMessage);
    }

    @Test
    public void testMessageGenerationWithInvalidTokenTrue() {
        String type = "role_token";
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", type, 1234567890L, true, "example.domain");

        String expectedMessage = "Fail to get token of type " + type + ".  Will not re-attempt to fetch token as token is invalid.";
        assertEquals(notification.getMessage(), expectedMessage);
    }

    @Test
    public void testMessageGenerationWithNullType() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", null, 1234567890L, false, "example.domain");

        String expectedMessage = "Fail to get token of type null. ";
        assertEquals(notification.getMessage(), expectedMessage);
    }

    @Test
    public void testMessageGenerationWithNullTypeAndInvalidToken() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", null, 1234567890L, true, "example.domain");

        String expectedMessage = "Fail to get token of type null.  Will not re-attempt to fetch token as token is invalid.";
        assertEquals(notification.getMessage(), expectedMessage);
    }

    @Test
    public void testGetExpirationZero() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", 0L, false, "example.domain");

        assertEquals(notification.getExpiration(), 0L);
    }

    @Test
    public void testGetExpirationNegative() {
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", -1L, false, "example.domain");

        assertEquals(notification.getExpiration(), -1L);
    }

    @Test
    public void testGetExpirationLargeValue() {
        long largeValue = Long.MAX_VALUE;
        ZTSClientNotification notification = new ZTSClientNotification(
                "https://zts.example.com", "admin", "access_token", largeValue, false, "example.domain");

        assertEquals(notification.getExpiration(), largeValue);
    }
}

