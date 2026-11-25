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
package com.yahoo.athenz.auth.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.token.RoleToken;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class TokenCredentialLoggingTest {

    // Deliberately invalid inputs: these tests do not need signing keys or usable credentials.
    private static final String CREDENTIAL_MARKER = "credential-must-not-be-logged";
    private static final String UNSIGNED_MARKER = "parsed-field-for-diagnostics";
    private static final String SIGNATURE_MARKER = "signature-must-not-be-logged";
    private static final String PRINCIPAL_TOKEN = "v=S1;d=domain;n=service;a=" + UNSIGNED_MARKER;
    private static final String ROLE_TOKEN = "v=Z1;d=domain;r=reader;p=domain.service;a=" + UNSIGNED_MARKER;

    private Logger logger;
    private Level previousLevel;
    private boolean previousAdditive;
    private ListAppender<ILoggingEvent> appender;

    @BeforeMethod
    public void captureLogs() {
        logger = (Logger) LoggerFactory.getLogger("com.yahoo.athenz.auth");
        previousLevel = logger.getLevel();
        previousAdditive = logger.isAdditive();
        logger.setLevel(Level.DEBUG);
        logger.setAdditive(false);
        appender = new ListAppender<>();
        appender.setContext(logger.getLoggerContext());
        appender.start();
        logger.addAppender(appender);
    }

    @AfterMethod(alwaysRun = true)
    public void restoreLogging() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(previousLevel);
        logger.setAdditive(previousAdditive);
    }

    @DataProvider
    public Object[][] unparseableCredentials() {
        List<Object[]> cases = new ArrayList<>();
        for (Level level : List.of(Level.INFO, Level.DEBUG)) {
            for (String credential : new String[] {
                    null,
                    "",
                    CREDENTIAL_MARKER,
                    CREDENTIAL_MARKER + ".payload.signature",
                    "Bearer " + CREDENTIAL_MARKER + ".payload.signature",
                    "v=S1;d=domain;n=service;r=reader;t=" + CREDENTIAL_MARKER,
                    "v=S1;d=domain;n=service;r=reader;e=" + CREDENTIAL_MARKER}) {
                cases.add(new Object[] {level, credential});
            }
        }
        return cases.toArray(new Object[0][]);
    }

    @Test(dataProvider = "unparseableCredentials")
    public void testParseFailuresDoNotExposeCredentials(Level level, String credential) {
        logger.setLevel(level);
        for (Authority authority : List.of(new PrincipalAuthority(), new RoleAuthority())) {
            StringBuilder errMsg = new StringBuilder();
            assertNull(authority.authenticate(credential, "127.0.0.1", "GET", errMsg));
            assertNoCredentials(errMsg);
            assertTrue(errMsg.toString().contains("Invalid token"));
        }
    }

    @Test
    public void testRoleCompleteFlagParseFailureDoesNotExposeInput() {
        StringBuilder errMsg = new StringBuilder();
        assertNull(new RoleAuthority().authenticate(ROLE_TOKEN + ";c=" + CREDENTIAL_MARKER,
                "127.0.0.1", "GET", errMsg));
        assertNoCredentials(errMsg);
        assertTrue(errMsg.toString().contains("NumberFormatException"));
    }

    @Test
    public void testValidationFailuresRetainUnsignedDiagnostics() {
        for (Authority authority : List.of(new PrincipalAuthority(), new RoleAuthority())) {
            ((AuthorityKeyStore) authority).setKeyStore((domain, service, keyId) -> null);
            String credential = authority instanceof PrincipalAuthority ? PRINCIPAL_TOKEN : ROLE_TOKEN;
            StringBuilder errMsg = new StringBuilder();
            assertNull(authority.authenticate(credential + ";s=" + SIGNATURE_MARKER,
                    "127.0.0.1", "GET", errMsg));
            assertTrue(errMsg.toString().contains("validation"));
            assertTrue(errMsg.toString().contains(credential));
            assertTrue(appender.list.stream().anyMatch(event ->
                    event.getFormattedMessage().contains("No public key provided")));
            assertNoCredentials(errMsg);
        }
    }

    @DataProvider
    public Object[][] invalidAuthorizedServices() {
        return new Object[][] {
                {";b=domain.service;s=" + SIGNATURE_MARKER},
                {";s=" + SIGNATURE_MARKER + ";bs=" + SIGNATURE_MARKER},
                {";b=domain.service;s=" + SIGNATURE_MARKER + ";bn=domain.other"
                        + ";bs=" + SIGNATURE_MARKER},
                {";b=domain.one,domain.two;s=" + SIGNATURE_MARKER + ";bs=" + SIGNATURE_MARKER}
        };
    }

    @Test(dataProvider = "invalidAuthorizedServices")
    public void testAuthorizedServiceFailuresRetainUnsignedDiagnostics(String suffix) {
        StringBuilder errMsg = new StringBuilder();
        assertNull(new PrincipalAuthority().authenticate(PRINCIPAL_TOKEN + suffix,
                "127.0.0.1", "GET", errMsg));
        assertTrue(errMsg.toString().contains("Invalid authorized service token"));
        assertTrue(errMsg.toString().contains(PRINCIPAL_TOKEN));
        assertNoCredentials(errMsg);
    }

    @Test
    public void testAuthorizedServiceValidationRetainsUnsignedDiagnostics() {
        PrincipalToken token = new PrincipalToken(PRINCIPAL_TOKEN + ";s=" + SIGNATURE_MARKER);
        StringBuilder errMsg = new StringBuilder();
        assertFalse(token.validateForAuthorizedService(null, errMsg));
        assertTrue(errMsg.toString().contains("missing data/signature component"));
        assertTrue(errMsg.toString().contains(PRINCIPAL_TOKEN));
        assertNoCredentials(errMsg);

        token = new PrincipalToken(PRINCIPAL_TOKEN + ";b=domain.service;s=" + SIGNATURE_MARKER
                + ";bs=" + SIGNATURE_MARKER);
        errMsg = new StringBuilder();
        assertFalse(token.validateForAuthorizedService(null, errMsg));
        assertTrue(errMsg.toString().contains("No public key provided"));
        assertTrue(errMsg.toString().contains(PRINCIPAL_TOKEN));
        assertNoCredentials(errMsg);
    }

    @Test
    public void testTokenCreationAndParsingRetainUnsignedDiagnostics() {
        PrincipalToken principalToken = new PrincipalToken.Builder("S1", "domain", "service")
                .salt(UNSIGNED_MARKER).authorizedServices(List.of("domain.service")).build();
        RoleToken roleToken = new RoleToken.Builder("Z1", "domain", List.of("reader"))
                .salt(UNSIGNED_MARKER).principal("domain.service").build();
        PrincipalToken parsedPrincipal = new PrincipalToken(principalToken.getUnsignedToken()
                + ";s=" + SIGNATURE_MARKER + ";bs=" + SIGNATURE_MARKER);
        RoleToken parsedRole = new RoleToken(roleToken.getUnsignedToken() + ";s=" + SIGNATURE_MARKER);
        assertEquals(parsedPrincipal.getName(), "service");
        assertEquals(parsedPrincipal.getSignature(), SIGNATURE_MARKER);
        assertEquals(parsedPrincipal.getAuthorizedServiceSignature(), SIGNATURE_MARKER);
        assertEquals(parsedRole.getRoles(), List.of("reader"));
        assertEquals(parsedRole.getSignature(), SIGNATURE_MARKER);
        assertTrue(appender.list.stream().anyMatch(event ->
                event.getFormattedMessage().contains(principalToken.getUnsignedToken())));
        assertTrue(appender.list.stream().anyMatch(event ->
                event.getFormattedMessage().contains(roleToken.getUnsignedToken())));
        assertNoCredentials(new StringBuilder());
    }

    private void assertNoCredentials(StringBuilder errMsg) {
        assertFalse(errMsg.toString().contains(CREDENTIAL_MARKER), "Error details exposed credential input");
        assertFalse(errMsg.toString().contains(SIGNATURE_MARKER), "Error details exposed a signature");
        assertFalse(appender.list.isEmpty(), "Expected diagnostic logs to be captured");
        for (ILoggingEvent event : appender.list) {
            assertFalse(event.getFormattedMessage().contains(CREDENTIAL_MARKER),
                    "Log message exposed credential input");
            assertFalse(event.getFormattedMessage().contains(SIGNATURE_MARKER),
                    "Log message exposed a signature");
            assertNull(event.getThrowableProxy(), "Raw parser exceptions must not be logged");
        }
    }
}
