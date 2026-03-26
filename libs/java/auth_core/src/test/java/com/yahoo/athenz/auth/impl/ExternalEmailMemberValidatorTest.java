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

import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.Set;

import static com.yahoo.athenz.auth.impl.ExternalEmailMemberValidator.PROP_VALID_EMAIL_DOMAINS;
import static org.testng.Assert.*;

public class ExternalEmailMemberValidatorTest {

    @AfterMethod
    public void cleanup() {
        System.clearProperty(PROP_VALID_EMAIL_DOMAINS);
    }

    @Test
    public void testValidEmailNoDomainRestriction() {
        ExternalEmailMemberValidator validator = new ExternalEmailMemberValidator();
        assertTrue(validator.getValidEmailDomains().isEmpty());
        assertTrue(validator.validateMember("sports", "user@example.com"));
        assertTrue(validator.validateMember("sports", "first.last@company.org"));
        assertTrue(validator.validateMember("sports", "user+tag@domain.co.uk"));
    }

    @Test
    public void testValidEmailWithDomainRestriction() {
        System.setProperty(PROP_VALID_EMAIL_DOMAINS, "example.com,corp.net");
        ExternalEmailMemberValidator validator = new ExternalEmailMemberValidator();
        assertEquals(validator.getValidEmailDomains(), Set.of("example.com", "corp.net"));

        assertTrue(validator.validateMember("sports", "user@example.com"));
        assertTrue(validator.validateMember("sports", "admin@corp.net"));
        assertFalse(validator.validateMember("sports", "user@other.com"));
    }

    @Test
    public void testDomainMatchingCaseInsensitive() {
        System.setProperty(PROP_VALID_EMAIL_DOMAINS, "Example.COM");
        ExternalEmailMemberValidator validator = new ExternalEmailMemberValidator();
        assertTrue(validator.validateMember("sports", "user@example.com"));
        assertTrue(validator.validateMember("sports", "user@EXAMPLE.COM"));
    }

    @Test
    public void testInvalidEmailAddresses() {
        ExternalEmailMemberValidator validator = new ExternalEmailMemberValidator();
        assertFalse(validator.validateMember("sports", null));
        assertFalse(validator.validateMember("sports", ""));
        assertFalse(validator.validateMember("sports", "not-an-email"));
        assertFalse(validator.validateMember("sports", "@missing-local.com"));
        assertFalse(validator.validateMember("sports", "missing-domain@"));
        assertFalse(validator.validateMember("sports", "user@.com"));
        assertFalse(validator.validateMember("sports", "user@domain"));
    }

    @Test
    public void testParseEmailDomainsEdgeCases() {
        assertTrue(ExternalEmailMemberValidator.parseEmailDomains(null).isEmpty());
        assertTrue(ExternalEmailMemberValidator.parseEmailDomains("").isEmpty());
        assertTrue(ExternalEmailMemberValidator.parseEmailDomains("  ,  , ").isEmpty());

        Set<String> domains = ExternalEmailMemberValidator.parseEmailDomains(" foo.com , bar.org , ");
        assertEquals(domains, Set.of("foo.com", "bar.org"));
    }

    @Test
    public void testDomainPropertyWithSpaces() {
        System.setProperty(PROP_VALID_EMAIL_DOMAINS, " example.com , corp.net ");
        ExternalEmailMemberValidator validator = new ExternalEmailMemberValidator();
        assertTrue(validator.validateMember("sports", "user@example.com"));
        assertTrue(validator.validateMember("sports", "user@corp.net"));
    }
}
