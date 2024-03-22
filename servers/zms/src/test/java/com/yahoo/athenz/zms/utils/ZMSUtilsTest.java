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
package com.yahoo.athenz.zms.utils;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory;
import com.yahoo.athenz.zms.*;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.utils.ZMSUtils.emptyIfNull;
import static org.testng.Assert.*;

public class ZMSUtilsTest {

    @Test
    public void testRemoveDomainPrefix() {
        assertEquals("role1", ZMSUtils.removeDomainPrefix("role1", "domain1", "role."));
        assertEquals("role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain1", "role."));
        assertEquals("domain1:role.role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain2", "role."));
        assertEquals("domain1:role.role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain1", "policy."));
        assertEquals("policy1", ZMSUtils.removeDomainPrefix("domain1:policy.policy1", "domain1", "policy."));
    }

    @Test
    public void testGetTenantResourceGroupRolePrefix() {

        assertEquals("storage.tenant.sports.api.",
                ZMSUtils.getTenantResourceGroupRolePrefix("storage", "sports.api", null));
        assertEquals("storage.tenant.sports.api.res_group.",
                ZMSUtils.getTenantResourceGroupRolePrefix("storage", "sports.api", ""));
        assertEquals("storage.tenant.sports.api.res_group.Group1.",
                ZMSUtils.getTenantResourceGroupRolePrefix("storage", "sports.api", "Group1"));
    }

    @Test
    public void testGetTrustedResourceGroupRolePrefix() {
        assertEquals("coretech:role.storage.tenant.sports.api.",
                ZMSUtils.getTrustedResourceGroupRolePrefix("coretech", "storage", "sports.api", null));
        assertEquals("coretech:role.storage.tenant.sports.api.",
                ZMSUtils.getTrustedResourceGroupRolePrefix("coretech", "storage", "sports.api", ""));
        assertEquals("coretech:role.storage.tenant.sports.api.res_group.group1.",
                ZMSUtils.getTrustedResourceGroupRolePrefix("coretech", "storage", "sports.api", "group1"));
    }

    @Test
    public void testGetProviderResourceGroupRolePrefix() {
        assertEquals("sports.hosted.res_group.hockey.",
                ZMSUtils.getProviderResourceGroupRolePrefix("sports", "hosted", "hockey"));
        assertEquals("sports.hosted.",
                ZMSUtils.getProviderResourceGroupRolePrefix("sports", "hosted", null));
        assertEquals("sports.hosted.",
                ZMSUtils.getProviderResourceGroupRolePrefix("sports", "hosted", ""));
    }

    @Test
    public void testParseBoolean() {
        assertTrue(ZMSUtils.parseBoolean(null, true));
        assertFalse(ZMSUtils.parseBoolean(null, false));
        assertTrue(ZMSUtils.parseBoolean("", true));
        assertFalse(ZMSUtils.parseBoolean("", false));
        assertTrue(ZMSUtils.parseBoolean("true", false));
        assertFalse(ZMSUtils.parseBoolean("false", true));
        assertFalse(ZMSUtils.parseBoolean("unknown", false));
    }

    @Test
    public void testAddAssertion() {

        Policy policy = new Policy();
        ZMSUtils.addAssertion(policy, "service", "update", "writers", AssertionEffect.ALLOW);
        ZMSUtils.addAssertion(policy, "table", "delete", "writers", AssertionEffect.DENY);

        assertEquals(policy.getAssertions().size(), 2);
        Assertion assertion = policy.getAssertions().get(1);
        assertEquals(assertion.getResource(), "table");
        assertEquals(assertion.getRole(), "writers");
        assertEquals(assertion.getAction(), "delete");
        assertEquals(assertion.getEffect(), AssertionEffect.DENY);
    }

    @Test
    public void testRemoveDomainPrefixForService() {

        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.api", "athenz"), "api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.dev.api", "athenz.dev"), "api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.dev.api", "athenz"), "dev.api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.api", "coretech"), "athenz.api");
    }

    @Test
    public void testGetAudtLogMsgBuilder() {

        List<String> roles = Arrays.asList("role1", "role2");
        Principal principal = SimplePrincipal.create("athenz", "creds", roles, null);
        RsrcCtxWrapper ctx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(ctx.principal()).thenReturn(principal);
        HttpServletRequestWrapper request = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(ctx.request()).thenReturn(request);
        Mockito.when(request.getRemoteAddr()).thenReturn("10.11.12.13");

        AuditLoggerFactory factory = new DefaultAuditLoggerFactory();
        AuditLogger auditLogger = factory.create();

        AuditLogMsgBuilder msgBuilder = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger, "athenz",
                "audit-ref", "unit-test", "putRole");
        assertNotNull(msgBuilder);
        assertTrue(msgBuilder.who().contains("who-roles=[role1, role2]"), msgBuilder.who());
    }
    
    @Test
    public void testPrincipalType() {
        // Set different strings between user and home domain
        String userDomain = "user";
        String userDomain2 = "user2";
        String homeDomain = "home";
        String headlessDomain = "headless";
        String topLevelDomain = "athenz";
        String groupSep = ":group";
        List<String> addlUserCheckDomainPrefixList = Arrays.asList(userDomain2);

        // GROUP
        assertEquals(ZMSUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(ZMSUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(ZMSUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER);
        assertEquals(ZMSUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(ZMSUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(ZMSUtils.principalType(topLevelDomain + ".test-service", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(ZMSUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        
        // Set same strings between user and home domain.
        userDomain = "personal";
        homeDomain = userDomain;
    
        // GROUP
        assertEquals(ZMSUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(ZMSUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(ZMSUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER);
        assertEquals(ZMSUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(ZMSUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(ZMSUtils.principalType(topLevelDomain + ".test-service", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(ZMSUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain, addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
    }

    @Test
    public void testExtractRoleName() {

        assertEquals("role1", ZMSUtils.extractRoleName("my-domain1", "my-domain1:role.role1"));
        assertEquals("role1.role2", ZMSUtils.extractRoleName("my-domain1", "my-domain1:role.role1.role2"));

        // invalid roles names
        assertNull(ZMSUtils.extractRoleName("my-domain1", "my-domain1:role1"));
        assertNull(ZMSUtils.extractRoleName("my-domain1", "my-domain2:role.role1"));
        assertNull(ZMSUtils.extractRoleName("my-domain1", "my-domain11:role.role1"));
        assertNull(ZMSUtils.extractRoleName("my-domain1", ":role.role1"));
        assertNull(ZMSUtils.extractRoleName("my-domain1", "role1"));
        assertNull(ZMSUtils.extractRoleName("my-domain1", "role1.role2"));
    }

    @Test
    public void testExtractEntityName() {

        assertEquals("entity1", ZMSUtils.extractEntityName("my-domain1", "my-domain1:entity.entity1"));
        assertEquals("entity1.entity2", ZMSUtils.extractEntityName("my-domain1", "my-domain1:entity.entity1.entity2"));

        // invalid entity names
        assertNull(ZMSUtils.extractEntityName("my-domain1", "my-domain1:entity1"));
        assertNull(ZMSUtils.extractEntityName("my-domain1", "my-domain2:entity.entity1"));
        assertNull(ZMSUtils.extractEntityName("my-domain1", "my-domain11:entity.entity1"));
        assertNull(ZMSUtils.extractEntityName("my-domain1", ":entity.entity1"));
        assertNull(ZMSUtils.extractEntityName("my-domain1", "entity1"));
        assertNull(ZMSUtils.extractEntityName("my-domain1", "entity1.entity2"));
    }

    @Test
    public void testExtractServiceName() {

        assertEquals("service1", ZMSUtils.extractServiceName("my-domain1", "my-domain1.service1"));
        assertEquals("service1", ZMSUtils.extractServiceName("my-domain1.domain2", "my-domain1.domain2.service1"));

        // invalid service names
        assertNull(ZMSUtils.extractServiceName("my-domain1", "my-domain1:service1"));
        assertNull(ZMSUtils.extractServiceName("my-domain1", "my-domain2.service1"));
        assertNull(ZMSUtils.extractServiceName("my-domain1", "my-domain11:service.service1"));
        assertNull(ZMSUtils.extractServiceName("my-domain1", ".service1"));
        assertNull(ZMSUtils.extractServiceName("my-domain1", "service1"));
        assertNull(ZMSUtils.extractServiceName("my-domain1", "service1.service2"));
    }

    @Test
    public void testExtractPolicyName() {

        assertEquals("policy1", ZMSUtils.extractPolicyName("my-domain1", "my-domain1:policy.policy1"));
        assertEquals("policy1.policy2", ZMSUtils.extractPolicyName("my-domain1", "my-domain1:policy.policy1.policy2"));

        // invalid policies names
        assertNull(ZMSUtils.extractPolicyName("my-domain1", "my-domain1:policy1"));
        assertNull(ZMSUtils.extractPolicyName("my-domain1", "my-domain2:policy.policy1"));
        assertNull(ZMSUtils.extractPolicyName("my-domain1", "my-domain11:policy.policy1"));
        assertNull(ZMSUtils.extractPolicyName("my-domain1", ":policy.policy1"));
        assertNull(ZMSUtils.extractPolicyName("my-domain1", "policy1"));
        assertNull(ZMSUtils.extractPolicyName("my-domain1", "policy1.policy2"));
    }

    @Test
    public void testIsUserAuthorityFilterValid() {

        Authority mockAuthority = Mockito.mock(Authority.class);
        Mockito.when(mockAuthority.isAttributeSet("user.john", "contractor")).thenReturn(true);
        Mockito.when(mockAuthority.isAttributeSet("user.john", "employee")).thenReturn(false);
        Mockito.when(mockAuthority.isAttributeSet("user.john", "local")).thenReturn(true);

        // non-users are always false
        assertFalse(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "filterList", "athenz.test"));

        // single filter value
        assertTrue(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "contractor", "user.john"));
        assertFalse(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "employee", "user.john"));

        // multiple values
        assertTrue(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "contractor,local", "user.john"));
        assertTrue(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "local,contractor", "user.john"));
        assertFalse(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "local,contractor,employee", "user.john"));
        assertFalse(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "local,employee,contractor", "user.john"));
        assertFalse(ZMSUtils.isUserAuthorityFilterValid(mockAuthority, "employee,contractor", "user.john"));
    }

    @Test
    public void testCombineUserAuthorityFilters() {

        assertNull(ZMSUtils.combineUserAuthorityFilters(null, null));
        assertNull(ZMSUtils.combineUserAuthorityFilters(null, ""));
        assertNull(ZMSUtils.combineUserAuthorityFilters("", null));
        assertNull(ZMSUtils.combineUserAuthorityFilters("", ""));

        assertEquals("role", ZMSUtils.combineUserAuthorityFilters("role", null));
        assertEquals("role", ZMSUtils.combineUserAuthorityFilters("role", ""));

        assertEquals("domain", ZMSUtils.combineUserAuthorityFilters(null, "domain"));
        assertEquals("domain", ZMSUtils.combineUserAuthorityFilters("", "domain"));

        assertEquals("role,domain", ZMSUtils.combineUserAuthorityFilters("role", "domain"));
        assertEquals("same,same", ZMSUtils.combineUserAuthorityFilters("same", "same"));
    }

    @Test
    public void testLowerDomainInResource() {
        assertEquals(ZMSUtils.lowerDomainInResource("DOMAIN:ResourcE1"), "domain:ResourcE1");
        assertEquals(ZMSUtils.lowerDomainInResource("domain:ResOurcE1"), "domain:ResOurcE1");
        assertEquals(ZMSUtils.lowerDomainInResource("domain:resource1"), "domain:resource1");
        assertEquals(ZMSUtils.lowerDomainInResource("DOMAIN:ResourcE2(ResourcE3)"), "domain:ResourcE2(ResourcE3)");
        assertEquals(ZMSUtils.lowerDomainInResource("DOMAIN:ResourcE1/ResourcE2"), "domain:ResourcE1/ResourcE2");
        assertEquals(ZMSUtils.lowerDomainInResource("DOMAIN:resource4[*]/data1"), "domain:resource4[*]/data1");
        assertEquals(ZMSUtils.lowerDomainInResource("justResource"), "justResource");
        assertEquals(ZMSUtils.lowerDomainInResource("WrongDelimiter.NoOp"), "WrongDelimiter.NoOp");
        assertEquals(ZMSUtils.lowerDomainInResource("DOMAIN:Many:Delimiters:THIS:TIME"), "domain:Many:Delimiters:THIS:TIME");
        assertEquals(ZMSUtils.lowerDomainInResource(""), "");
        assertNull(ZMSUtils.lowerDomainInResource(null));
    }

    @Test
    public void testUserAuthorityAttrPresent() {

        // empty role filter cases

        assertFalse(ZMSUtils.userAuthorityAttrMissing(null, "test1"));
        assertFalse(ZMSUtils.userAuthorityAttrMissing("", "test1"));

        // if role filter is not empty but group is - then failure

        assertTrue(ZMSUtils.userAuthorityAttrMissing("test1", null));
        assertTrue(ZMSUtils.userAuthorityAttrMissing("test1", ""));

        // values match

        assertFalse(ZMSUtils.userAuthorityAttrMissing("test1", "test1"));
        assertFalse(ZMSUtils.userAuthorityAttrMissing("test1,test2", "test1,test2"));

        // array value match

        assertFalse(ZMSUtils.userAuthorityAttrMissing("test2,test3,test1", "test1,test3,test2"));

        // subset values match

        assertFalse(ZMSUtils.userAuthorityAttrMissing("test2,test3", "test1,test3,test2"));
        assertFalse(ZMSUtils.userAuthorityAttrMissing("test3", "test1,test3,test2"));

        // mismatch values

        assertTrue(ZMSUtils.userAuthorityAttrMissing("test1", "test2"));
        assertTrue(ZMSUtils.userAuthorityAttrMissing("test2,test3,test1", "test4,test3,test2"));
    }

    @Test
    public void testCreatePrincipalForName() {

        String userDomain = "user";
        String userDomainAlias = null;

        Principal principal = ZMSUtils.createPrincipalForName("joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe");

        principal = ZMSUtils.createPrincipalForName("joe-smith", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe-smith");

        principal = ZMSUtils.createPrincipalForName("user.joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe");

        principal = ZMSUtils.createPrincipalForName("user.joe.storage", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe.storage");

        principal = ZMSUtils.createPrincipalForName("alias.joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "alias.joe");

        principal = ZMSUtils.createPrincipalForName("alias.joe.storage", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "alias.joe.storage");

        userDomainAlias = "alias";

        principal = ZMSUtils.createPrincipalForName("joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe");

        principal = ZMSUtils.createPrincipalForName("joe-smith", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe-smith");

        principal = ZMSUtils.createPrincipalForName("user.joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe");

        principal = ZMSUtils.createPrincipalForName("user.joe.storage", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe.storage");

        principal = ZMSUtils.createPrincipalForName("alias.joe", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "user.joe");

        principal = ZMSUtils.createPrincipalForName("alias.joe.storage", userDomain, userDomainAlias);
        assertEquals(principal.getFullName(), "alias.joe.storage");
    }

    @Test
    public void testEmitMonmetricError() {

        Metric savedMetric = ZMSImpl.metric;
        assertFalse(ZMSUtils.emitMonmetricError(-1, "unittest"));
        assertFalse(ZMSUtils.emitMonmetricError(400, null));
        assertFalse(ZMSUtils.emitMonmetricError(400, ""));
        ZMSImpl.metric = null;
        assertFalse(ZMSUtils.emitMonmetricError(400, "unittest"));
        ZMSImpl.metric = savedMetric;
    }

    @Test
    public void testMetaValueChanged() {
        assertTrue(ZMSUtils.metaValueChanged("account-1", "account-2"));
        assertFalse(ZMSUtils.metaValueChanged("account-1", "account-1"));

        assertTrue(ZMSUtils.metaValueChanged(null, "account-1"));
        assertFalse(ZMSUtils.metaValueChanged(null, null));
        assertFalse(ZMSUtils.metaValueChanged("account-1", null));

        assertTrue(ZMSUtils.metaValueChanged(10, 15));
        assertFalse(ZMSUtils.metaValueChanged(10, 10));

        assertTrue(ZMSUtils.metaValueChanged(null, 10));
        assertFalse(ZMSUtils.metaValueChanged(10, null));
    }

    @Test
    public void testConfiguredExpiryMillis() {

        assertEquals(ZMSUtils.configuredDueDateMillis(null, null), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(null, -3), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(null, 0), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(-3, null), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(0, null), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(-3, -3), 0);
        assertEquals(ZMSUtils.configuredDueDateMillis(0, 0), 0);

        long extMillis = TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS);
        long millis = ZMSUtils.configuredDueDateMillis(null, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(null, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(-1, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(0, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(5, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(20, 10);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));

        millis = ZMSUtils.configuredDueDateMillis(10, null);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(10, -1);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
        millis = ZMSUtils.configuredDueDateMillis(10, 0);
        assertTrue(ZMSTestUtils.validateDueDate(millis, extMillis));
    }

    @Test
    public void testEmptyIfNull() {
        Collection<String> l = emptyIfNull(null);
        assertEquals(l.size(), 0);

        l = emptyIfNull(Collections.emptyList());
        assertEquals(l.size(), 0);

        l = emptyIfNull(Collections.singletonList("s"));
        assertEquals(l.size(), 1);
    }
}
