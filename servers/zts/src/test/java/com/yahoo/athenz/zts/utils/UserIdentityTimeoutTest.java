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

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.TagValueList;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class UserIdentityTimeoutTest {

    private UserIdentityTimeout userIdentityTimeout;

    @AfterMethod
    public void cleanup() {
        if (userIdentityTimeout != null) {
            userIdentityTimeout.close();
            userIdentityTimeout = null;
        }
    }

    private Role createRoleWithTimeout(String roleName, String timeoutValue) {
        Role role = new Role().setName(roleName);
        if (timeoutValue != null) {
            Map<String, TagValueList> tags = new HashMap<>();
            TagValueList tagValueList = new TagValueList();
            tagValueList.setList(Collections.singletonList(timeoutValue));
            tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
            role.setTags(tags);
        }
        return role;
    }

    private Role createRoleWithTokenTimeout(String roleName, String timeoutValue) {
        Role role = new Role().setName(roleName);
        if (timeoutValue != null) {
            Map<String, TagValueList> tags = new HashMap<>();
            TagValueList tagValueList = new TagValueList();
            tagValueList.setList(Collections.singletonList(timeoutValue));
            tags.put(ZTSConsts.ZTS_USER_TOKEN_TIMEOUT_TAG, tagValueList);
            role.setTags(tags);
        }
        return role;
    }

    private Role createRoleWithBothTimeouts(String roleName, String certTimeoutValue, String tokenTimeoutValue) {
        Role role = new Role().setName(roleName);
        Map<String, TagValueList> tags = new HashMap<>();
        if (certTimeoutValue != null) {
            TagValueList certTag = new TagValueList();
            certTag.setList(Collections.singletonList(certTimeoutValue));
            tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, certTag);
        }
        if (tokenTimeoutValue != null) {
            TagValueList tokenTag = new TagValueList();
            tokenTag.setList(Collections.singletonList(tokenTimeoutValue));
            tags.put(ZTSConsts.ZTS_USER_TOKEN_TIMEOUT_TAG, tokenTag);
        }
        role.setTags(tags);
        return role;
    }

    private Role createRoleWithoutTimeout(String roleName) {
        return new Role().setName(roleName);
    }

    @Test
    public void testConstructorWithRolesHavingTimeoutTag() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));
        roles.add(createRoleWithTimeout("user:role.developer", "120"));
        roles.add(createRoleWithoutTimeout("user:role.reader"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.developer"), Integer.valueOf(120));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.reader"));
        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);
    }

    @Test
    public void testConstructorNullDomainData() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testConstructorNullRoles() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        DomainData domainData = new DomainData()
                .setName("user")
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testConstructorNoRolesWithTag() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithoutTimeout("user:role.admin"));
        roles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testExtractTimeoutFromRoleNull() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertNull(userIdentityTimeout.extractTimeoutFromRole(null, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleNullTags() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleNoTimeoutTag() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tagValueList.setList(Collections.singletonList("true"));
        tags.put("zts.IssueRoleCerts", tagValueList);
        role.setTags(tags);

        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleNullTagValueList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, null);
        role.setTags(tags);

        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleEmptyTagList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tagValueList.setList(Collections.emptyList());
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
        role.setTags(tags);

        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleNullListInTagValueList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
        role.setTags(tags);

        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleInvalidNumber() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = createRoleWithTimeout("user:role.test", "not-a-number");

        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG));
    }

    @Test
    public void testExtractTimeoutFromRoleValidValue() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = createRoleWithTimeout("user:role.test", "30");

        assertEquals(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG), Integer.valueOf(30));
    }

    @Test
    public void testRefreshIfModifiedDomainNotModified() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));

        // calling refreshIfModified with same timestamp should not change anything

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
    }

    @Test
    public void testRefreshIfModifiedDomainModified() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));

        // update domain with a new timestamp and changed roles

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "90"));
        updatedRoles.add(createRoleWithTimeout("user:role.ops", "30"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(90));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.ops"), Integer.valueOf(30));
    }

    @Test
    public void testRefreshIfModifiedNullDomainData() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);

        // domain data becomes null (e.g. domain removed from cache)

        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout.refreshIfModified();

        // map should remain unchanged since we couldn't fetch domain data

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
    }

    @Test
    public void testRefreshRemovesDeletedRoleTags() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));
        roles.add(createRoleWithTimeout("user:role.developer", "120"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);

        // remove the tag from the developer role

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.developer"));
    }

    @Test
    public void testRefreshRemovesDeletedRoles() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));
        roles.add(createRoleWithTimeout("user:role.developer", "120"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);

        // completely remove the developer role from the domain

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.developer"));
    }

    @Test
    public void testRefreshWithNullRolesClearsMap() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);

        // domain now has null roles

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testRefreshWithNullModifiedTimestamp() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles);
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
    }

    @Test
    public void testRefreshIfModifiedNullModifiedTimestamp() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles);
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        // with null modified timestamp, modifiedMillis defaults to 0, so
        // 0 > 0 is false and no refresh should happen

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
    }

    @Test
    public void testGetTimeoutNonExistentRole() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertNull(userIdentityTimeout.getCertTimeout("user:role.nonexistent"));
    }

    @Test
    public void testGetTimeoutMapUnmodifiable() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Map<String, Integer> timeoutMap = userIdentityTimeout.getCertTimeoutMap();
        try {
            timeoutMap.put("user:role.test", 100);
            fail();
        } catch (UnsupportedOperationException ignored) {
        }
    }

    @Test
    public void testRefreshIfModifiedExceptionHandled() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        // now make getDomainData throw an exception

        when(dataStore.getDomainData("user")).thenThrow(new RuntimeException("test exception"));

        // should not throw, exception is caught internally

        userIdentityTimeout.refreshIfModified();

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testRefreshTimeoutMapNullDomainData() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        // directly call refreshTimeoutMap with null domain

        userIdentityTimeout.refreshTimeoutMap(null);

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testMultipleRolesWithMixedTags() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.short-lived", "15"));
        roles.add(createRoleWithTimeout("user:role.standard", "60"));
        roles.add(createRoleWithTimeout("user:role.long-lived", "1440"));
        roles.add(createRoleWithoutTimeout("user:role.no-timeout"));
        roles.add(createRoleWithTimeout("user:role.invalid", "abc"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 3);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.short-lived"), Integer.valueOf(15));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.standard"), Integer.valueOf(60));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.long-lived"), Integer.valueOf(1440));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.no-timeout"));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.invalid"));
    }

    @Test
    public void testRefreshAddsNewRoles() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);

        // add new roles with timeout tags

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));
        updatedRoles.add(createRoleWithTimeout("user:role.new-role", "45"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.new-role"), Integer.valueOf(45));
    }

    @Test
    public void testRefreshUpdatesExistingTimeout() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));

        // update the timeout value

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "120"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(120));
    }

    @Test
    public void testClose() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        // should not throw

        userIdentityTimeout.close();
        userIdentityTimeout = null;
    }

    @Test
    public void testRefreshAllTagsRemoved() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTimeout("user:role.admin", "60"));
        roles.add(createRoleWithTimeout("user:role.developer", "120"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);

        // remove all timeout tags from all roles

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithoutTimeout("user:role.admin"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    private void mockAccessibleRoles(DataStore dataStore, DataCache dataCache, Set<String> returnedRoles) {
        when(dataStore.getDataCache("user")).thenReturn(dataCache);
        doAnswer(invocation -> {
            Set<String> roles = invocation.getArgument(5);
            roles.addAll(returnedRoles);
            return null;
        }).when(dataStore).getAccessibleRoles(eq(dataCache), eq("user"), anyString(),
                isNull(), eq(false), anySet(), eq(true));
    }

    @Test
    public void testgetUserCertTimeoutNullDataCache() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);
            when(dataStore.getDataCache("user")).thenReturn(null);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutNoRolesNoUserRequested() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "30"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutOnlyUserRequested() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 30 < default 60 -> certTimeout=30, min(30, 120) = 30
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 30), 30);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutOnlyRoleTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "90"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // no user requested, role timeout 90 -> min(90, 120) = 90
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 90);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutBothPresent() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "50"));
            roles.add(createRoleWithTimeout("user:role.developer", "80"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            accessibleRoles.add("user:role.developer");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 70 < role timeout 80 -> certTimeout=70, min(70, 120) = 70
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 70), 70);

            // user requested 100 > role timeout 80 -> certTimeout stays 80, min(80, 120) = 80
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 100), 80);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutCappedByMax() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "200"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // role timeout 200, no user request -> certTimeout=200, min(200, 120) = 120
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 120);

            // user requested 150 < role timeout 200 -> certTimeout=150, min(150, 120) = 120
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 150), 120);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutUserRequestedZero() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 0 is treated as absent, no role timeout -> default
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 0), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutRolesWithNoTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithoutTimeout("user:role.reader"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.reader");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user is member of role.reader which has no timeout tag -> default
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutUserRequestedNegative() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // negative user request is treated as absent -> default 60, min(60, 120) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", -10), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutUserRequestedSmallerThanRoleTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "90"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 45 < role timeout 90 -> certTimeout=45, min(45, 120) = 45
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 45), 45);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutUserRequestedLargerThanRoleTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "90"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 100 > role timeout 90 -> certTimeout stays 90, min(90, 120) = 90
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 100), 90);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutDefaultExceedsMax() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "200");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max (120) < default (200) -> constructor sets max = default (200)
            // no role timeout -> default 200, min(200, 200) = 200
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testgetUserCertTimeoutUserRequestedLargerThanDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 90 > default 60 -> certTimeout stays 60, min(60, 120) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", 90), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserRoleTimeoutMultipleRolesMaxWins() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "300");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.low", "30"));
            roles.add(createRoleWithTimeout("user:role.mid", "120"));
            roles.add(createRoleWithTimeout("user:role.high", "240"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.low");
            accessibleRoles.add("user:role.mid");
            accessibleRoles.add("user:role.high");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max role timeout = 240, no user request -> min(240, 300) = 240
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 240);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorCustomRefreshInterval() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_IDENTITY_TIMEOUT_REFRESH_INTERVAL, "5");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_IDENTITY_TIMEOUT_REFRESH_INTERVAL);
        }
    }

    @Test
    public void testConstructorNegativeDefaultTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "-10");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was -10 -> reset to 60, max 120 is valid -> min(60, 120) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorZeroDefaultTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "0");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was 0 -> reset to 60, max 120 is valid -> min(60, 120) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorNegativeMaxTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "-5");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "90"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max was -5 -> reset to 60, default 60 is valid, max (60) >= default (60) ok
            // role timeout 90, min(90, 60) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorZeroMaxTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "0");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "90"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max was 0 -> reset to 60, default 60 is valid, max (60) >= default (60) ok
            // role timeout 90, min(90, 60) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorBothNegativeTimeoutsResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "-10");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "-20");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // both reset to 60, max (60) >= default (60) ok -> min(60, 60) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorMaxLessThanDefaultBothSetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "100");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "50");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTimeout("user:role.admin", "200"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max (50) < default (100) -> max set to 100
            // role timeout 200, min(200, 100) = 100
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 100);

            // no role timeout -> default 100, min(100, 100) = 100
            when(dataStore.getDataCache("user")).thenReturn(null);
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.jane", null), 100);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorMaxEqualsDefaultNoReset() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "100");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "100");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // both are 100, max >= default -> no adjustment, min(100, 100) = 100
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 100);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorNegativeDefaultValidMaxAdjusted() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "-5");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "30");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was -5 -> reset to 60, max 30 is valid but 30 < 60 -> max set to 60
            // no role timeout -> default 60, min(60, 60) = 60
            assertEquals(userIdentityTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testTokenTimeoutBasicFunctionality() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));
        roles.add(createRoleWithTokenTimeout("user:role.developer", "7200"));
        roles.add(createRoleWithoutTimeout("user:role.reader"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(3600));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.developer"), Integer.valueOf(7200));
        assertNull(userIdentityTimeout.getTokenTimeout("user:role.reader"));
        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 2);
        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
    }

    @Test
    public void testTokenTimeoutMapUnmodifiable() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Map<String, Integer> tokenMap = userIdentityTimeout.getTokenTimeoutMap();
        try {
            tokenMap.put("user:role.test", 100);
            fail();
        } catch (UnsupportedOperationException ignored) {
        }
    }

    @Test
    public void testGetTokenTimeoutNonExistentRole() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertNull(userIdentityTimeout.getTokenTimeout("user:role.nonexistent"));
    }

    @Test
    public void testExtractTimeoutFromRoleTokenTag() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = createRoleWithTokenTimeout("user:role.test", "1800");
        assertEquals(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_TOKEN_TIMEOUT_TAG),
                Integer.valueOf(1800));
    }

    @Test
    public void testExtractTimeoutFromRoleTokenTagInvalidNumber() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = createRoleWithTokenTimeout("user:role.test", "not-a-number");
        assertNull(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_TOKEN_TIMEOUT_TAG));
    }

    @Test
    public void testRolesWithBothCertAndTokenTimeouts() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithBothTimeouts("user:role.admin", "60", "3600"));
        roles.add(createRoleWithBothTimeouts("user:role.developer", "120", "7200"));
        roles.add(createRoleWithTimeout("user:role.certonly", "90"));
        roles.add(createRoleWithTokenTimeout("user:role.tokenonly", "1800"));
        roles.add(createRoleWithoutTimeout("user:role.notags"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 3);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.developer"), Integer.valueOf(120));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.certonly"), Integer.valueOf(90));
        assertNull(userIdentityTimeout.getCertTimeout("user:role.tokenonly"));

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 3);
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(3600));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.developer"), Integer.valueOf(7200));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.tokenonly"), Integer.valueOf(1800));
        assertNull(userIdentityTimeout.getTokenTimeout("user:role.certonly"));
    }

    @Test
    public void testRefreshWithNullRolesClearsBothMaps() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithBothTimeouts("user:role.admin", "60", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 1);

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
        assertTrue(userIdentityTimeout.getTokenTimeoutMap().isEmpty());
    }

    @Test
    public void testRefreshRemovesDeletedTokenRoleTags() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));
        roles.add(createRoleWithTokenTimeout("user:role.developer", "7200"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 2);

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(3600));
        assertNull(userIdentityTimeout.getTokenTimeout("user:role.developer"));
    }

    @Test
    public void testRefreshUpdatesTokenTimeout() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(3600));

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTokenTimeout("user:role.admin", "7200"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(7200));
    }

    @Test
    public void testGetUserTokenTimeoutNullDataCache() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);
            when(dataStore.getDataCache("user")).thenReturn(null);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutNoRolesNoUserRequested() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "1800"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutOnlyRoleTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "7200"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // role timeout 7200, no user request -> min(7200, 43200) = 7200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 7200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutOnlyUserRequested() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 1800 < default 3600 -> timeout=1800, min(1800, 43200) = 1800
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", 1800), 1800);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutBothPresent() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "7200"));
            roles.add(createRoleWithTokenTimeout("user:role.developer", "10800"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            accessibleRoles.add("user:role.developer");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 5000 < max role timeout 10800 -> timeout=5000, min(5000, 43200) = 5000
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", 5000), 5000);

            // user requested 15000 > max role timeout 10800 -> timeout stays 10800, min(10800, 43200) = 10800
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", 15000), 10800);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutCappedByMax() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "7200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "14400"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // role timeout 14400, no user request -> min(14400, 7200) = 7200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 7200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutUserRequestedZero() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 0 is treated as absent -> default 3600
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", 0), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutUserRequestedNegative() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // negative user request is treated as absent -> default 3600
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", -10), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutMultipleRolesMaxWins() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.low", "1800"));
            roles.add(createRoleWithTokenTimeout("user:role.mid", "7200"));
            roles.add(createRoleWithTokenTimeout("user:role.high", "14400"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.low");
            accessibleRoles.add("user:role.mid");
            accessibleRoles.add("user:role.high");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max role timeout = 14400, no user request -> min(14400, 43200) = 14400
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 14400);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutRolesWithNoTimeout() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithoutTimeout("user:role.reader"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.reader");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user is member of role.reader which has no token timeout tag -> default
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorNegativeTokenDefaultTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "-10");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was -10 -> reset to 43200 (the timeout variable at that point)
            // max 43200 >= default 43200 -> ok
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorZeroTokenDefaultTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "0");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was 0 -> reset to 43200 (the timeout variable at that point)
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorNegativeTokenMaxTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "-5");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "50000"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max was -5 -> reset to 43200, default 3600 valid, max (43200) >= default (3600)
            // role timeout 50000, min(50000, 43200) = 43200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorZeroTokenMaxTimeoutResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "0");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);

            List<Role> roles = new ArrayList<>();
            roles.add(createRoleWithTokenTimeout("user:role.admin", "50000"));

            DomainData domainData = new DomainData()
                    .setName("user")
                    .setRoles(roles)
                    .setModified(Timestamp.fromMillis(1000));
            when(dataStore.getDomainData("user")).thenReturn(domainData);

            DataCache dataCache = Mockito.mock(DataCache.class);
            Set<String> accessibleRoles = new HashSet<>();
            accessibleRoles.add("user:role.admin");
            mockAccessibleRoles(dataStore, dataCache, accessibleRoles);

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max was 0 -> reset to 43200, default 3600 valid, max (43200) >= default (3600)
            // role timeout 50000, min(50000, 43200) = 43200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorTokenMaxLessThanDefaultBothSetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "7200");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "3600");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max (3600) < default (7200) -> max set to 7200
            // no role timeout -> default 7200, min(7200, 7200) = 7200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 7200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorBothNegativeTokenTimeoutsResetToDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "-10");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "-20");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was -10 -> reset to 43200 (timeout var holds 43200 at that point)
            // max was -20 -> reset to 43200
            // max (43200) >= default (43200) -> ok
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testRefreshAllTokenTagsRemoved() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));
        roles.add(createRoleWithTokenTimeout("user:role.developer", "7200"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 2);

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithoutTimeout("user:role.admin"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertTrue(userIdentityTimeout.getTokenTimeoutMap().isEmpty());
    }

    @Test
    public void testGetUserTokenTimeoutUserRequestedLargerThanDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // user requested 7200 > default 3600 -> timeout stays 3600
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", 7200), 3600);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserTokenTimeoutDefaultExceedsMax() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "50000");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // max (43200) < default (50000) -> max set to 50000
            // no role timeout -> default 50000, min(50000, 50000) = 50000
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 50000);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }

    @Test
    public void testExtractTimeoutFromRoleWithWhitespace() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tagValueList.setList(Collections.singletonList("  120  "));
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
        role.setTags(tags);

        assertEquals(userIdentityTimeout.extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG),
                Integer.valueOf(120));
    }

    @Test
    public void testGetUserIdentityTimeoutDirectly() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        // userExpiryRequested is null -> no change, min(100, 200) = 100
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, null), 100);

        // userExpiryRequested > timeout -> no change, min(100, 200) = 100
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, 150), 100);

        // userExpiryRequested < timeout -> timeout updated, min(50, 200) = 50
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, 50), 50);

        // timeout > maxTimeout -> capped, min(300, 200) = 200
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(300, 200, null), 200);

        // userExpiryRequested == timeout -> no change (not less than), min(100, 200) = 100
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, 100), 100);

        // userExpiryRequested == 0 -> treated as absent, min(100, 200) = 100
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, 0), 100);

        // userExpiryRequested < 0 -> treated as absent, min(100, 200) = 100
        assertEquals(userIdentityTimeout.getUserIdentityTimeout(100, 200, -5), 100);
    }

    @Test
    public void testRefreshTokenMapWithDomainDataPassedDirectly() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> initialRoles = new ArrayList<>();
        initialRoles.add(createRoleWithTokenTimeout("user:role.admin", "3600"));

        DomainData initialDomainData = new DomainData()
                .setName("user")
                .setRoles(initialRoles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(initialDomainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 1);

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTokenTimeout("user:role.admin", "7200"));
        updatedRoles.add(createRoleWithTokenTimeout("user:role.ops", "1800"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));

        userIdentityTimeout.refreshTimeoutMap(updatedDomainData);

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 2);
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(7200));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.ops"), Integer.valueOf(1800));
    }

    @Test
    public void testRefreshBothMapsSimultaneously() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithBothTimeouts("user:role.admin", "60", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(3600));

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithBothTimeouts("user:role.admin", "120", "7200"));
        updatedRoles.add(createRoleWithBothTimeouts("user:role.ops", "30", "1800"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshIfModified();

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 2);
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(120));
        assertEquals(userIdentityTimeout.getCertTimeout("user:role.ops"), Integer.valueOf(30));

        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 2);
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(7200));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.ops"), Integer.valueOf(1800));
    }

    @Test
    public void testRefreshWithNullRolesAndNullModifiedTimestamp() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithBothTimeouts("user:role.admin", "60", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        assertEquals(userIdentityTimeout.getCertTimeoutMap().size(), 1);
        assertEquals(userIdentityTimeout.getTokenTimeoutMap().size(), 1);

        DomainData updatedDomainData = new DomainData()
                .setName("user");
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userIdentityTimeout.refreshTimeoutMap(updatedDomainData);

        assertTrue(userIdentityTimeout.getCertTimeoutMap().isEmpty());
        assertTrue(userIdentityTimeout.getTokenTimeoutMap().isEmpty());
    }

    @Test
    public void testRefreshWithRolesAndNullModifiedTimestamp() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        List<Role> roles = new ArrayList<>();
        roles.add(createRoleWithBothTimeouts("user:role.admin", "60", "3600"));

        DomainData domainData = new DomainData()
                .setName("user")
                .setRoles(roles)
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithBothTimeouts("user:role.admin", "120", "7200"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles);

        userIdentityTimeout.refreshTimeoutMap(updatedDomainData);

        assertEquals(userIdentityTimeout.getCertTimeout("user:role.admin"), Integer.valueOf(120));
        assertEquals(userIdentityTimeout.getTokenTimeout("user:role.admin"), Integer.valueOf(7200));
    }

    @Test
    public void testConstructorNegativeTokenDefaultValidMaxAdjusted() {

        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "-5");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "1800");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userIdentityTimeout = new UserIdentityTimeout(dataStore, "user");

            // default was -5 -> reset to 43200 (timeout var = 43200 at that point)
            // max 1800 is valid but 1800 < 43200 -> max set to 43200
            assertEquals(userIdentityTimeout.getUserTokenTimeout("user.john", null), 43200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT);
        }
    }
}
