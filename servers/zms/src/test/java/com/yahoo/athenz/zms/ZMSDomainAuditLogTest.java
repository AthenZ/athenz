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

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.log.AuditLogHistoryQuery;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.*;

public class ZMSDomainAuditLogTest {

    private static final String AUDIT_LOG_DOMAIN = "audit-log-domain";

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
        zmsTestInitializer.createTopLevelDomain(AUDIT_LOG_DOMAIN);
    }

    @AfterMethod
    public void shutDown() {
        zmsTestInitializer.deleteTopLevelDomain(AUDIT_LOG_DOMAIN);
        zmsTestInitializer.shutDown();
    }

    @Test
    public void testGetDomainAuditLogNotSupported() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        // default audit logger does not support history so we
        // should get back an empty list

        DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null,
                null, null, null, null);
        assertNotNull(auditLog);
        assertTrue(auditLog.getEntries().isEmpty());
    }

    @Test
    public void testGetDomainAuditLogDefaults() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        DomainAuditLogEntry entry = new DomainAuditLogEntry().setApi("putRole").setEntity("readers")
                .setPrincipal("user.joe").setClientIp("10.1.1.1").setTimestamp(Timestamp.fromCurrentTime())
                .setJustification("ticket-1234").setDetails("{\"member\": \"user.jane\"}");
        DomainAuditLog mockAuditLog = new DomainAuditLog().setEntries(Collections.singletonList(entry));

        AuditLogger savedLogger = zmsImpl.dbService.auditLogger;
        AuditLogger mockLogger = Mockito.mock(AuditLogger.class);
        Mockito.when(mockLogger.getDomainAuditLogHistory(any())).thenReturn(mockAuditLog);
        zmsImpl.dbService.auditLogger = mockLogger;

        try {
            long now = System.currentTimeMillis();
            DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(ctx, "Audit-Log-Domain", null, null,
                    null, null, null, null);
            assertEquals(auditLog, mockAuditLog);

            ArgumentCaptor<AuditLogHistoryQuery> captor = ArgumentCaptor.forClass(AuditLogHistoryQuery.class);
            Mockito.verify(mockLogger).getDomainAuditLogHistory(captor.capture());
            AuditLogHistoryQuery query = captor.getValue();

            assertEquals(query.getDomainName(), "audit-log-domain");
            assertNull(query.getApi());
            assertNull(query.getEntity());
            assertNull(query.getPrincipal());
            assertEquals(query.getLimit(), 100);

            // end time must be the current time and start time 30 days before

            assertTrue(query.getEndTime().millis() >= now);
            assertTrue(query.getEndTime().millis() <= System.currentTimeMillis());
            assertEquals(query.getEndTime().millis() - query.getStartTime().millis(),
                    TimeUnit.DAYS.toMillis(30));
        } finally {
            zmsImpl.dbService.auditLogger = savedLogger;
        }
    }

    @Test
    public void testGetDomainAuditLogWithFilters() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        AuditLogger savedLogger = zmsImpl.dbService.auditLogger;
        AuditLogger mockLogger = Mockito.mock(AuditLogger.class);
        Mockito.when(mockLogger.getDomainAuditLogHistory(any())).thenReturn(new DomainAuditLog());
        zmsImpl.dbService.auditLogger = mockLogger;

        try {
            // null entries from the logger must be returned as an empty list

            DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", "putRole",
                    "Readers", "User.Joe", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00-07:00", 10);
            assertTrue(auditLog.getEntries().isEmpty());

            ArgumentCaptor<AuditLogHistoryQuery> captor = ArgumentCaptor.forClass(AuditLogHistoryQuery.class);
            Mockito.verify(mockLogger).getDomainAuditLogHistory(captor.capture());
            AuditLogHistoryQuery query = captor.getValue();

            assertEquals(query.getDomainName(), "audit-log-domain");
            assertEquals(query.getApi(), "putRole");
            assertEquals(query.getEntity(), "readers");
            assertEquals(query.getPrincipal(), "user.joe");
            assertEquals(query.getStartTime(), Timestamp.fromString("2026-09-01T00:00:00Z"));
            assertEquals(query.getEndTime(), Timestamp.fromString("2026-09-02T07:00:00Z"));
            assertEquals(query.getLimit(), 10);

            // only end date specified - start is 30 days before the end date
            // and a limit above the max value is capped at the max value

            Mockito.clearInvocations(mockLogger);
            zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", "", "", "", "",
                    "2026-09-02T00:00:00Z", 5000);
            Mockito.verify(mockLogger).getDomainAuditLogHistory(captor.capture());
            query = captor.getValue();

            assertNull(query.getApi());
            assertNull(query.getEntity());
            assertNull(query.getPrincipal());
            assertEquals(query.getEndTime(), Timestamp.fromString("2026-09-02T00:00:00Z"));
            assertEquals(query.getStartTime(), Timestamp.fromString("2026-08-03T00:00:00Z"));
            assertEquals(query.getLimit(), 1000);

            // start and end dates are the same

            Mockito.clearInvocations(mockLogger);
            zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null, null,
                    "2026-09-02T00:00:00Z", "2026-09-02T00:00:00Z", null);
            Mockito.verify(mockLogger).getDomainAuditLogHistory(captor.capture());
            query = captor.getValue();
            assertEquals(query.getStartTime(), query.getEndTime());
        } finally {
            zmsImpl.dbService.auditLogger = savedLogger;
        }
    }

    @Test
    public void testGetDomainAuditLogPartialResults() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        List<DomainAuditLogEntry> entries = new ArrayList<>();
        long now = System.currentTimeMillis();
        for (int i = 0; i < 5; i++) {
            entries.add(new DomainAuditLogEntry().setApi("putRole").setEntity("role" + i)
                    .setPrincipal("user.joe").setTimestamp(Timestamp.fromMillis(now - i * 1000L)));
        }

        AuditLogger savedLogger = zmsImpl.dbService.auditLogger;
        AuditLogger mockLogger = Mockito.mock(AuditLogger.class);
        zmsImpl.dbService.auditLogger = mockLogger;

        try {
            // the result set and partial flag are determined by the audit
            // logger implementation and returned by the server as is

            DomainAuditLog mockAuditLog = new DomainAuditLog().setEntries(entries.subList(0, 3)).setPartial(true);
            Mockito.when(mockLogger.getDomainAuditLogHistory(any())).thenReturn(mockAuditLog);
            DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null,
                    null, null, null, 3);
            assertEquals(auditLog.getEntries(), entries.subList(0, 3));
            assertTrue(auditLog.getPartial());

            mockAuditLog = new DomainAuditLog().setEntries(entries).setPartial(false);
            Mockito.when(mockLogger.getDomainAuditLogHistory(any())).thenReturn(mockAuditLog);
            auditLog = zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null,
                    null, null, null, 3);
            assertEquals(auditLog.getEntries(), entries);
            assertFalse(auditLog.getPartial());

            mockAuditLog = new DomainAuditLog().setEntries(entries);
            Mockito.when(mockLogger.getDomainAuditLogHistory(any())).thenReturn(mockAuditLog);
            auditLog = zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null,
                    null, null, null, 10);
            assertEquals(auditLog.getEntries(), entries);
            assertNull(auditLog.getPartial());
        } finally {
            zmsImpl.dbService.auditLogger = savedLogger;
        }
    }

    @Test
    public void testGetDomainAuditLogInvalidArguments() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        // invalid domain name

        verifyBadRequest(zmsImpl, ctx, "invalid domain!", null, null, null, null, null, null, null);

        // invalid api, entity and principal names

        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", "put role", null, null, null, null, null, null);
        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, "readers role", null, null, null, null, null);
        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, "user joe", null, null, null, null);

        // invalid start and end dates

        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, null, "2026-09-01",
                null, null, "invalid start date");
        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, null, null,
                "not-a-date", null, "invalid end date");

        // start date after end date

        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, null, "2026-09-02T00:00:00Z",
                "2026-09-01T00:00:00Z", null, "start date must not be after end date");

        // invalid limit values

        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, null, null, null, 0,
                "limit must be a positive number");
        verifyBadRequest(zmsImpl, ctx, "audit-log-domain", null, null, null, null, null, -1,
                "limit must be a positive number");
    }

    private void verifyBadRequest(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, final String domainName,
            final String api, final String entity, final String principal, final String startDate,
            final String endDate, Integer limit, final String message) {
        try {
            zmsImpl.getDomainAuditLog(ctx, domainName, api, entity, principal, startDate, endDate, limit);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            if (message != null) {
                assertTrue(ex.getMessage().contains(message), ex.getMessage());
            }
        }
    }

    @Test
    public void testGetDomainAuditLogFailure() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog");

        AuditLogger savedLogger = zmsImpl.dbService.auditLogger;
        AuditLogger mockLogger = Mockito.mock(AuditLogger.class);
        Mockito.when(mockLogger.getDomainAuditLogHistory(any()))
                .thenThrow(new ServerResourceException(ServerResourceException.INTERNAL_SERVER_ERROR, "backend failure"));
        zmsImpl.dbService.auditLogger = mockLogger;

        try {
            zmsImpl.getDomainAuditLog(ctx, "audit-log-domain", null, null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("backend failure"));
        } finally {
            zmsImpl.dbService.auditLogger = savedLogger;
        }
    }

    @Test
    public void testGetDomainAuditLogDomainNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        try {
            zmsImpl.getDomainAuditLog(ctx, "unknown-audit-log-domain", null, null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    @Test
    public void testGetDomainAuditLogAuthorization() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String otherDomain = "audit-log-other-domain";

        RsrcCtxWrapper userCtx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog", "john");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.john"));

        // without any authorization the request is rejected

        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        // authorizing the principal in another domain does not grant
        // access to the audit log of our domain

        zmsTestInitializer.createTopLevelDomain(otherDomain);
        Role role = zmsTestInitializer.createRoleObject(otherDomain, "audit-log-role", null, roleMembers);
        zmsImpl.putRole(ctx, otherDomain, "audit-log-role", auditRef, false, null, role);
        Policy policy = zmsTestInitializer.createPolicyObject(otherDomain, "audit-log-policy", "audit-log-role",
                "access", otherDomain + ":meta.audit.log", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, otherDomain, "audit-log-policy", auditRef, false, null, policy);

        assertNotNull(zmsImpl.getDomainAuditLog(userCtx, otherDomain, null, null, null, null, null, null));
        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        // now authorize the principal at the domain level

        role = zmsTestInitializer.createRoleObject(AUDIT_LOG_DOMAIN, "audit-log-role", null, roleMembers);
        zmsImpl.putRole(ctx, AUDIT_LOG_DOMAIN, "audit-log-role", auditRef, false, null, role);
        policy = zmsTestInitializer.createPolicyObject(AUDIT_LOG_DOMAIN, "audit-log-policy", "audit-log-role",
                "access", AUDIT_LOG_DOMAIN + ":meta.audit.log", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, AUDIT_LOG_DOMAIN, "audit-log-policy", auditRef, false, null, policy);

        DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(userCtx, AUDIT_LOG_DOMAIN, null, null,
                null, null, null, null);
        assertTrue(auditLog.getEntries().isEmpty());

        // a different action on the same resource is not sufficient

        policy = zmsTestInitializer.createPolicyObject(AUDIT_LOG_DOMAIN, "audit-log-policy", "audit-log-role",
                "read", AUDIT_LOG_DOMAIN + ":meta.audit.log", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, AUDIT_LOG_DOMAIN, "audit-log-policy", auditRef, false, null, policy);
        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        zmsImpl.deletePolicy(ctx, AUDIT_LOG_DOMAIN, "audit-log-policy", auditRef, null);
        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        // now authorize the principal at the system level which
        // grants access to the audit log of all domains

        role = zmsTestInitializer.createRoleObject("sys.auth", "audit-log-role", null, roleMembers);
        zmsImpl.putRole(ctx, "sys.auth", "audit-log-role", auditRef, false, null, role);
        policy = zmsTestInitializer.createPolicyObject("sys.auth", "audit-log-policy", "audit-log-role",
                "access", "sys.auth:meta.audit.log", AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "audit-log-policy", auditRef, false, null, policy);

        auditLog = zmsImpl.getDomainAuditLog(userCtx, AUDIT_LOG_DOMAIN, null, null, null, null, null, null);
        assertTrue(auditLog.getEntries().isEmpty());
        assertNotNull(zmsImpl.getDomainAuditLog(userCtx, otherDomain, null, null, null, null, null, null));

        zmsImpl.deletePolicy(ctx, "sys.auth", "audit-log-policy", auditRef, null);
        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        zmsImpl.deleteRole(ctx, "sys.auth", "audit-log-role", auditRef, null);
        zmsTestInitializer.deleteTopLevelDomain(otherDomain);
    }

    @Test
    public void testGetDomainAuditLogDomainAdmin() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();
        final String adminDomain = "audit-log-admin-domain";

        // a domain administrator has access to its own domain's audit log
        // through the admin policy but not to any other domain

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(adminDomain,
                "Test " + adminDomain, "testOrg", zmsTestInitializer.getAdminUser(), "user.jane");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        RsrcCtxWrapper userCtx = zmsTestInitializer.contextWithMockPrincipal("getDomainAuditLog", "jane");
        DomainAuditLog auditLog = zmsImpl.getDomainAuditLog(userCtx, adminDomain, null, null,
                null, null, null, null);
        assertTrue(auditLog.getEntries().isEmpty());
        verifyForbidden(zmsImpl, userCtx, AUDIT_LOG_DOMAIN);

        zmsTestInitializer.deleteTopLevelDomain(adminDomain);
    }

    private void verifyForbidden(ZMSImpl zmsImpl, RsrcCtxWrapper ctx, final String domainName) {
        try {
            zmsImpl.getDomainAuditLog(ctx, domainName, null, null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("not authorized to retrieve audit log"), ex.getMessage());
        }
    }

    @Test
    public void testAuditLogHistoryConfigSettings() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_MAX_LIMIT, "500");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_LIMIT, "50");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_DAYS, "7");
        zmsImpl.loadConfigurationSettings();
        assertEquals(zmsImpl.auditLogHistoryMaxLimit, 500);
        assertEquals(zmsImpl.auditLogHistoryDefaultLimit, 50);
        assertEquals(zmsImpl.auditLogHistoryDefaultDays, 7);

        // invalid values revert to defaults

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_MAX_LIMIT, "0");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_LIMIT, "-1");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_DAYS, "0");
        zmsImpl.loadConfigurationSettings();
        assertEquals(zmsImpl.auditLogHistoryMaxLimit, 1000);
        assertEquals(zmsImpl.auditLogHistoryDefaultLimit, 100);
        assertEquals(zmsImpl.auditLogHistoryDefaultDays, 30);

        // default limit cannot be larger than the max limit

        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_MAX_LIMIT, "20");
        System.setProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_LIMIT, "50");
        zmsImpl.loadConfigurationSettings();
        assertEquals(zmsImpl.auditLogHistoryMaxLimit, 20);
        assertEquals(zmsImpl.auditLogHistoryDefaultLimit, 20);

        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_MAX_LIMIT);
        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_LIMIT);
        System.clearProperty(ZMSConsts.ZMS_PROP_AUDIT_LOG_HISTORY_DEFAULT_DAYS);
        zmsImpl.loadConfigurationSettings();
        assertEquals(zmsImpl.auditLogHistoryMaxLimit, 1000);
        assertEquals(zmsImpl.auditLogHistoryDefaultLimit, 100);
        assertEquals(zmsImpl.auditLogHistoryDefaultDays, 30);
    }
}
