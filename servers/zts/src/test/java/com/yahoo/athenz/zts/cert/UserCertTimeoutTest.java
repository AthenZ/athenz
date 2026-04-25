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
package com.yahoo.athenz.zts.cert;

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

public class UserCertTimeoutTest {

    private UserCertTimeout userCertTimeout;

    @AfterMethod
    public void cleanup() {
        if (userCertTimeout != null) {
            userCertTimeout.close();
            userCertTimeout = null;
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userCertTimeout.getTimeout("user:role.developer"), Integer.valueOf(120));
        assertNull(userCertTimeout.getTimeout("user:role.reader"));
        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);
    }

    @Test
    public void testConstructorNullDomainData() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
    }

    @Test
    public void testConstructorNullRoles() {

        DataStore dataStore = Mockito.mock(DataStore.class);

        DomainData domainData = new DomainData()
                .setName("user")
                .setModified(Timestamp.fromMillis(1000));
        when(dataStore.getDomainData("user")).thenReturn(domainData);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
    }

    @Test
    public void testExtractTimeoutFromRoleNull() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertNull(userCertTimeout.extractTimeoutFromRole(null));
    }

    @Test
    public void testExtractTimeoutFromRoleNullTags() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleNoTimeoutTag() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tagValueList.setList(Collections.singletonList("true"));
        tags.put("zts.IssueRoleCerts", tagValueList);
        role.setTags(tags);

        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleNullTagValueList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, null);
        role.setTags(tags);

        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleEmptyTagList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tagValueList.setList(Collections.emptyList());
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
        role.setTags(tags);

        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleNullListInTagValueList() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = new Role().setName("user:role.test");
        Map<String, TagValueList> tags = new HashMap<>();
        TagValueList tagValueList = new TagValueList();
        tags.put(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG, tagValueList);
        role.setTags(tags);

        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleInvalidNumber() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = createRoleWithTimeout("user:role.test", "not-a-number");

        assertNull(userCertTimeout.extractTimeoutFromRole(role));
    }

    @Test
    public void testExtractTimeoutFromRoleValidValue() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Role role = createRoleWithTimeout("user:role.test", "30");

        assertEquals(userCertTimeout.extractTimeoutFromRole(role), Integer.valueOf(30));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));

        // calling refreshIfModified with same timestamp should not change anything

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));

        // update domain with a new timestamp and changed roles

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "90"));
        updatedRoles.add(createRoleWithTimeout("user:role.ops", "30"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(90));
        assertEquals(userCertTimeout.getTimeout("user:role.ops"), Integer.valueOf(30));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);

        // domain data becomes null (e.g. domain removed from cache)

        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout.refreshIfModified();

        // map should remain unchanged since we couldn't fetch domain data

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);

        // remove the tag from the developer role

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
        assertNull(userCertTimeout.getTimeout("user:role.developer"));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);

        // completely remove the developer role from the domain

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
        assertNull(userCertTimeout.getTimeout("user:role.developer"));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);

        // domain now has null roles

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        // with null modified timestamp, modifiedMillis defaults to 0, so
        // 0 > 0 is false and no refresh should happen

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);
    }

    @Test
    public void testGetTimeoutNonExistentRole() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertNull(userCertTimeout.getTimeout("user:role.nonexistent"));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        Map<String, Integer> timeoutMap = userCertTimeout.getTimeoutMap();
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        // now make getDomainData throw an exception

        when(dataStore.getDomainData("user")).thenThrow(new RuntimeException("test exception"));

        // should not throw, exception is caught internally

        userCertTimeout.refreshIfModified();

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
    }

    @Test
    public void testRefreshTimeoutMapNullDomainData() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        // directly call refreshTimeoutMap with null domain

        userCertTimeout.refreshTimeoutMap();

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 3);
        assertEquals(userCertTimeout.getTimeout("user:role.short-lived"), Integer.valueOf(15));
        assertEquals(userCertTimeout.getTimeout("user:role.standard"), Integer.valueOf(60));
        assertEquals(userCertTimeout.getTimeout("user:role.long-lived"), Integer.valueOf(1440));
        assertNull(userCertTimeout.getTimeout("user:role.no-timeout"));
        assertNull(userCertTimeout.getTimeout("user:role.invalid"));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 1);

        // add new roles with timeout tags

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "60"));
        updatedRoles.add(createRoleWithTimeout("user:role.new-role", "45"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);
        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));
        assertEquals(userCertTimeout.getTimeout("user:role.new-role"), Integer.valueOf(45));
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(60));

        // update the timeout value

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithTimeout("user:role.admin", "120"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertEquals(userCertTimeout.getTimeout("user:role.admin"), Integer.valueOf(120));
    }

    @Test
    public void testClose() {

        DataStore dataStore = Mockito.mock(DataStore.class);
        when(dataStore.getDomainData("user")).thenReturn(null);

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        // should not throw

        userCertTimeout.close();
        userCertTimeout = null;
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

        userCertTimeout = new UserCertTimeout(dataStore, "user");

        assertEquals(userCertTimeout.getTimeoutMap().size(), 2);

        // remove all timeout tags from all roles

        List<Role> updatedRoles = new ArrayList<>();
        updatedRoles.add(createRoleWithoutTimeout("user:role.admin"));
        updatedRoles.add(createRoleWithoutTimeout("user:role.developer"));

        DomainData updatedDomainData = new DomainData()
                .setName("user")
                .setRoles(updatedRoles)
                .setModified(Timestamp.fromMillis(2000));
        when(dataStore.getDomainData("user")).thenReturn(updatedDomainData);

        userCertTimeout.refreshIfModified();

        assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
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
    public void testGetUserCertTimeoutNullDataCache() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);
            when(dataStore.getDataCache("user")).thenReturn(null);

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutNoRolesNoUserRequested() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutOnlyUserRequested() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 30 < default 60 -> certTimeout=30, min(30, 120) = 30
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 30), 30);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutOnlyRoleTimeout() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // no user requested, role timeout 90 -> min(90, 120) = 90
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 90);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutBothPresent() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 70 < role timeout 80 -> certTimeout=70, min(70, 120) = 70
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 70), 70);

            // user requested 100 > role timeout 80 -> certTimeout stays 80, min(80, 120) = 80
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 100), 80);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutCappedByMax() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // role timeout 200, no user request -> certTimeout=200, min(200, 120) = 120
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 120);

            // user requested 150 < role timeout 200 -> certTimeout=150, min(150, 120) = 120
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 150), 120);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutUserRequestedZero() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 0 is treated as absent, no role timeout -> default
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 0), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutRolesWithNoTimeout() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user is member of role.reader which has no timeout tag -> default
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutUserRequestedNegative() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // negative user request is treated as absent -> default 60, min(60, 120) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", -10), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutUserRequestedSmallerThanRoleTimeout() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 45 < role timeout 90 -> certTimeout=45, min(45, 120) = 45
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 45), 45);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutUserRequestedLargerThanRoleTimeout() {

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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 100 > role timeout 90 -> certTimeout stays 90, min(90, 120) = 90
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 100), 90);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutDefaultExceedsMax() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "200");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // max (120) < default (200) -> constructor sets max = default (200)
            // no role timeout -> default 200, min(200, 200) = 200
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 200);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testGetUserCertTimeoutUserRequestedLargerThanDefault() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, "120");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            DataCache dataCache = Mockito.mock(DataCache.class);
            mockAccessibleRoles(dataStore, dataCache, Collections.emptySet());

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // user requested 90 > default 60 -> certTimeout stays 60, min(60, 120) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", 90), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // max role timeout = 240, no user request -> min(240, 300) = 240
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 240);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }

    @Test
    public void testConstructorCustomRefreshInterval() {

        System.setProperty(ZTSConsts.ZTS_PROP_USER_CERT_TIMEOUT_REFRESH_INTERVAL, "5");

        try {
            DataStore dataStore = Mockito.mock(DataStore.class);
            when(dataStore.getDomainData("user")).thenReturn(null);

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            assertTrue(userCertTimeout.getTimeoutMap().isEmpty());
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_TIMEOUT_REFRESH_INTERVAL);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // default was -10 -> reset to 60, max 120 is valid -> min(60, 120) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // default was 0 -> reset to 60, max 120 is valid -> min(60, 120) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // max was -5 -> reset to 60, default 60 is valid, max (60) >= default (60) ok
            // role timeout 90, min(90, 60) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // max was 0 -> reset to 60, default 60 is valid, max (60) >= default (60) ok
            // role timeout 90, min(90, 60) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // both reset to 60, max (60) >= default (60) ok -> min(60, 60) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // max (50) < default (100) -> max set to 100
            // role timeout 200, min(200, 100) = 100
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 100);

            // no role timeout -> default 100, min(100, 100) = 100
            when(dataStore.getDataCache("user")).thenReturn(null);
            assertEquals(userCertTimeout.getUserCertTimeout("user.jane", null), 100);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // both are 100, max >= default -> no adjustment, min(100, 100) = 100
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 100);
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

            userCertTimeout = new UserCertTimeout(dataStore, "user");

            // default was -5 -> reset to 60, max 30 is valid but 30 < 60 -> max set to 60
            // no role timeout -> default 60, min(60, 60) = 60
            assertEquals(userCertTimeout.getUserCertTimeout("user.john", null), 60);
        } finally {
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
            System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        }
    }
}
