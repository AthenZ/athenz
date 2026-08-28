/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.cert.impl;

import com.yahoo.athenz.common.server.cert.X509CertEmailValidator;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class DefaultX509CertEmailValidatorTest {

    @Test
    public void testValidateServiceCertificateEmailsNoEmails() {
        X509CertEmailValidator validator = new DefaultX509CertEmailValidator(false);

        List<String> emails = new ArrayList<>();
        assertTrue(validator.validateServiceCertificateEmails("domain", "service", emails));

        assertTrue(validator.validateServiceCertificateEmails("domain", "service", null));
    }

    @Test
    public void testValidateServiceCertificateEmailsWithEmailsRejectDisabled() {
        X509CertEmailValidator validator = new DefaultX509CertEmailValidator(false);

        List<String> emails = Arrays.asList("test@example.com");
        assertTrue(validator.validateServiceCertificateEmails("domain", "service", emails));
    }

    @Test
    public void testValidateServiceCertificateEmailsWithEmailsRejectEnabled() {
        X509CertEmailValidator validator = new DefaultX509CertEmailValidator(true);

        List<String> emails = Arrays.asList("test@example.com");
        assertFalse(validator.validateServiceCertificateEmails("domain", "service", emails));
    }

    @Test
    public void testValidateServiceCertificateEmailsMultipleEmailsRejectEnabled() {
        X509CertEmailValidator validator = new DefaultX509CertEmailValidator(true);

        List<String> emails = Arrays.asList("test1@example.com", "test2@example.com");
        assertFalse(validator.validateServiceCertificateEmails("domain", "service", emails));
    }

    @Test
    public void testValidateServiceCertificateEmailsMultipleEmailsRejectDisabled() {
        X509CertEmailValidator validator = new DefaultX509CertEmailValidator(false);

        List<String> emails = Arrays.asList("test1@example.com", "test2@example.com");
        assertTrue(validator.validateServiceCertificateEmails("domain", "service", emails));
    }
}
