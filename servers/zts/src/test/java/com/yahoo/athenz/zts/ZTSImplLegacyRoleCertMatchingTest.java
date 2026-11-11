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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.cert.X509RoleCertRequest;
import com.yahoo.athenz.zts.store.DataStore;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZTSImplLegacyRoleCertMatchingTest {

    private static final String DOMAIN = "sports";
    private static final String CALLER = "sports.api";
    private static final String PROXY = "user.jane";
    private static final String ROLE = "admin";
    private static final String SUFFIX_ROLE = "fc-admin";
    private static final String IP = "192.0.2.1";

    private ZTSImpl zts;
    private DataCache data;
    private ResourceContext context;
    private Principal principal;
    private X509RoleCertRequest csr;
    private RoleCertificateRequest request;
    private Logger logger;
    private Level previousLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeMethod
    public void setup() {
        // Exercise the shared Role Cert handler without loading signing keys or certificates.
        zts = mock(ZTSImpl.class, CALLS_REAL_METHODS);
        zts.metric = mock(Metric.class);
        zts.dataStore = mock(DataStore.class);
        zts.instanceCertManager = mock(InstanceCertManager.class);
        zts.validServiceX509CertSignerKeyIds = Set.of();
        zts.authorizedProxyUsers = Set.of(CALLER);

        data = mock(DataCache.class);
        when(zts.dataStore.getDataCache(DOMAIN)).thenReturn(data);

        context = mock(ResourceContext.class);
        when(context.getApiName()).thenReturn("postrolecertificaterequestext");
        principal = mock(Principal.class);
        when(principal.getFullName()).thenReturn(CALLER);
        when(principal.getDomain()).thenReturn(DOMAIN);
        when(principal.getName()).thenReturn("api");
        when(principal.getRoles()).thenReturn(null);

        csr = mock(X509RoleCertRequest.class);
        when(csr.getReqRoleDomain()).thenReturn(DOMAIN);
        when(csr.getReqRoleName()).thenReturn(ROLE);
        request = new RoleCertificateRequest().setExpiryTime(3600L);

        doReturn(true).when(zts).validateRoleCertificateRequest(eq(csr), anyString(), any(), any(), eq(IP));
        doReturn(60).when(zts).determineRoleCertTimeout(eq(data), anySet(), anyInt());
        doReturn(null).when(zts).getPrincipalDomainSignerKeyId(any(), anyString(), anyString(), any(), eq(true));
        when(zts.instanceCertManager.generateX509Certificate(isNull(), isNull(), isNull(),
                eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), eq(60), eq(Priority.High), isNull()))
                .thenReturn("signer-result");

        logger = (Logger) LoggerFactory.getLogger(ZTSImpl.class);
        previousLevel = logger.getLevel();
        logger.setLevel(Level.INFO);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterMethod
    public void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(previousLevel);
    }

    private void roles(String identity, Set<String> suffixMatches, Set<String> exactMatches) {
        doAnswer(invocation -> {
            boolean fullNameMatch = invocation.getArgument(4);
            Set<String> result = invocation.getArgument(5);
            result.addAll(fullNameMatch ? exactMatches : suffixMatches);
            return null;
        }).when(zts.dataStore).getAccessibleRoles(eq(data), eq(DOMAIN), eq(identity),
                aryEq(new String[] { ROLE }), anyBoolean(), anySet(), eq(false));
    }

    private String issue() {
        return zts.processRoleCertificateRequest(context, principal, DOMAIN, csr, IP, request);
    }

    private List<ILoggingEvent> diagnostics() {
        return appender.list.stream()
                .filter(event -> event.getMessage().startsWith("rolecert_legacy_match "))
                .collect(Collectors.toList());
    }

    private void assertRejected(int status) {
        ResourceException exception = expectThrows(ResourceException.class, this::issue);
        assertEquals(exception.getCode(), status);
        verifyNoInteractions(zts.instanceCertManager);
        assertTrue(diagnostics().isEmpty());
    }

    @DataProvider
    public Object[][] apiNames() {
        return new Object[][] {
                { "postrolecertificaterequest" },
                { "postrolecertificaterequestext" }
        };
    }

    @DataProvider
    public Object[][] matchingModes() {
        return new Object[][] { { false }, { true } };
    }

    @DataProvider
    public Object[][] settings() {
        return new Object[][] {
                { null, false }, { "false", false }, { "true", true },
                { "TRUE", true }, { "", false }, { "invalid", false }
        };
    }

    @Test(dataProvider = "settings")
    public void testConfiguration(String value, boolean expected) {
        String property = ZTSConsts.ZTS_PROP_ALLOW_LEGACY_ROLE_CERT_MATCHING;
        String previous = System.getProperty(property);
        try {
            if (value == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, value);
            }
            zts.loadConfigurationSettings();
            assertEquals(zts.allowLegacyRoleCertMatching, expected);
        } finally {
            if (previous == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, previous);
            }
        }
    }

    @Test(dataProvider = "apiNames")
    public void testDefaultRejectsSuffixOnlyMembership(String api) {
        when(context.getApiName()).thenReturn(api);
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of());

        assertRejected(ResourceException.FORBIDDEN);
        verify(zts.dataStore).getAccessibleRoles(eq(data), eq(DOMAIN), eq(CALLER),
                aryEq(new String[] { ROLE }), eq(true), anySet(), eq(false));
    }

    @Test(dataProvider = "apiNames")
    public void testLegacyAllowsSuffixOnlyMembershipAndLogs(String api) {
        when(context.getApiName()).thenReturn(api);
        zts.allowLegacyRoleCertMatching = true;
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of());

        assertEquals(issue(), "signer-result");
        assertFalse(zts.logUnrequestedRolesEnabled);
        assertEquals(diagnostics().size(), 1);
        assertEquals(diagnostics().get(0).getLevel(), Level.INFO);
        assertEquals(diagnostics().get(0).getFormattedMessage(),
                "rolecert_legacy_match api=" + api + " principal=" + CALLER
                        + " proxy_for=null domain=" + DOMAIN + " requested_role=" + ROLE
                        + " matched_roles=" + SUFFIX_ROLE);
        verify(zts.dataStore).getAccessibleRoles(eq(data), eq(DOMAIN), eq(CALLER),
                aryEq(new String[] { ROLE }), eq(false), anySet(), eq(false));
    }

    @Test(dataProvider = "matchingModes")
    public void testExactMembershipDoesNotLog(boolean legacy) {
        zts.allowLegacyRoleCertMatching = legacy;
        roles(CALLER, Set.of(ROLE, SUFFIX_ROLE), Set.of(ROLE));

        assertEquals(issue(), "signer-result");
        assertTrue(diagnostics().isEmpty());
    }

    @Test(dataProvider = "matchingModes")
    public void testNoMembershipIsRejected(boolean legacy) {
        zts.allowLegacyRoleCertMatching = legacy;
        roles(CALLER, Set.of(), Set.of());

        assertRejected(ResourceException.FORBIDDEN);
    }

    @Test
    public void testDefaultRejectsSuffixMatchesReturnedThroughGroupsOrTrust() {
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of(SUFFIX_ROLE));

        assertRejected(ResourceException.FORBIDDEN);
    }

    @Test(dataProvider = "matchingModes")
    public void testProxyWithOnlySharedSuffixMembership(boolean legacy) {
        zts.allowLegacyRoleCertMatching = legacy;
        request.setProxyForPrincipal(PROXY);
        roles(CALLER, Set.of(ROLE, SUFFIX_ROLE), Set.of(ROLE));
        roles(PROXY, Set.of(SUFFIX_ROLE), Set.of());

        if (legacy) {
            assertEquals(issue(), "signer-result");
            assertEquals(diagnostics().size(), 1);
            String message = diagnostics().get(0).getFormattedMessage();
            assertTrue(message.contains("principal=" + CALLER + " proxy_for=" + PROXY));
            assertTrue(message.contains("requested_role=" + ROLE + " matched_roles=" + SUFFIX_ROLE));
            verify(zts).validateRoleCertificateRequest(csr, PROXY, CALLER, null, IP);
        } else {
            assertRejected(ResourceException.FORBIDDEN);
        }
        verify(zts.dataStore).getAccessibleRoles(eq(data), eq(DOMAIN), eq(PROXY),
                aryEq(new String[] { ROLE }), eq(!legacy), anySet(), eq(false));
    }

    @Test
    public void testLegacyProxyRequiresSharedRole() {
        zts.allowLegacyRoleCertMatching = true;
        request.setProxyForPrincipal(PROXY);
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of());
        roles(PROXY, Set.of("other-admin"), Set.of());

        assertRejected(ResourceException.FORBIDDEN);
    }

    @Test
    public void testLegacyProxyExactMembershipDoesNotLog() {
        zts.allowLegacyRoleCertMatching = true;
        request.setProxyForPrincipal(PROXY);
        roles(CALLER, Set.of(ROLE, SUFFIX_ROLE), Set.of(ROLE));
        roles(PROXY, Set.of(ROLE, SUFFIX_ROLE), Set.of(ROLE));

        assertEquals(issue(), "signer-result");
        assertTrue(diagnostics().isEmpty());
    }

    @Test
    public void testLegacyUnauthorizedProxyIsRejected() {
        zts.allowLegacyRoleCertMatching = true;
        zts.authorizedProxyUsers = Set.of();
        request.setProxyForPrincipal(PROXY);

        assertRejected(ResourceException.FORBIDDEN);
        verifyNoInteractions(zts.dataStore);
    }

    @Test
    public void testLegacyInvalidRequestDoesNotLog() {
        zts.allowLegacyRoleCertMatching = true;
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of());
        doReturn(false).when(zts).validateRoleCertificateRequest(csr, CALLER, null, null, IP);

        assertRejected(ResourceException.BAD_REQUEST);
    }

    @Test
    public void testLegacySigningFailureDoesNotLog() {
        zts.allowLegacyRoleCertMatching = true;
        roles(CALLER, Set.of(SUFFIX_ROLE), Set.of());
        when(zts.instanceCertManager.generateX509Certificate(isNull(), isNull(), isNull(),
                eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), eq(60), eq(Priority.High), isNull()))
                .thenReturn(null);

        ResourceException exception = expectThrows(ResourceException.class, this::issue);
        assertEquals(exception.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
        assertTrue(diagnostics().isEmpty());
    }
}
