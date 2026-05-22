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
package com.yahoo.athenz.common.server.cert;

import com.yahoo.athenz.common.server.ServerResourceException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class CertificateDataValidatorTest {

    @Test
    public void testCertificateDataValidatorFactory() throws ServerResourceException {

        CertificateDataValidator validator = Mockito.mock(CertificateDataValidator.class);

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);
    }

    @Test
    public void testCertificateDataValidatorFactoryThrowsException() {

        CertificateDataValidatorFactory factory = () -> {
            throw new ServerResourceException(500, "factory failure");
        };

        try {
            factory.create();
            org.testng.Assert.fail("Expected ServerResourceException");
        } catch (ServerResourceException ex) {
            org.testng.Assert.assertEquals(ex.getCode(), 500);
            org.testng.Assert.assertEquals(ex.getMessage(), "factory failure");
        }
    }

    @Test
    public void testValidateServiceIdentityCertSanDnsName() throws ServerResourceException {

        CertificateDataValidator validator = Mockito.mock(CertificateDataValidator.class);
        List<String> providerDnsSuffixes = Collections.singletonList("provider.athenz.io");

        Mockito.when(validator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.athenz.io", "athenz.io", providerDnsSuffixes)).thenReturn(true);
        Mockito.when(validator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.invalid.io", "athenz.io", providerDnsSuffixes)).thenReturn(false);

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);

        assertTrue(testValidator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.athenz.io", "athenz.io", providerDnsSuffixes));
        assertFalse(testValidator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.invalid.io", "athenz.io", providerDnsSuffixes));
    }

    @Test
    public void testValidateServiceIdentityCertSanDnsNameNullSuffixes() throws ServerResourceException {

        CertificateDataValidator validator = Mockito.mock(CertificateDataValidator.class);

        Mockito.when(validator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.athenz.io", null, null)).thenReturn(true);

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);

        assertTrue(testValidator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.athenz.io", null, null));
    }

    @Test
    public void testValidateRoleCertSanDnsName() throws ServerResourceException {

        CertificateDataValidator validator = Mockito.mock(CertificateDataValidator.class);
        List<String> roleDnsSuffixList = Collections.singletonList("role.athenz.io");

        Mockito.when(validator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", roleDnsSuffixList)).thenReturn(true);
        Mockito.when(validator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.invalid.io", roleDnsSuffixList)).thenReturn(false);

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);

        assertTrue(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", roleDnsSuffixList));
        assertFalse(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.invalid.io", roleDnsSuffixList));
    }

    @Test
    public void testValidateRoleCertSanDnsNameNullSuffixList() throws ServerResourceException {

        CertificateDataValidator validator = Mockito.mock(CertificateDataValidator.class);

        Mockito.when(validator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", null)).thenReturn(false);

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);

        assertFalse(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", null));
    }

    @Test
    public void testCertificateDataValidatorCustomImplementation() throws ServerResourceException {

        CertificateDataValidator validator = new CertificateDataValidator() {
            @Override
            public boolean validateServiceIdentityCertSanDnsName(String domainName, String serviceName,
                    String dnsName, String serviceDnsSuffix, List<String> providerDnsSuffixes) {
                return dnsName != null && dnsName.endsWith(serviceDnsSuffix);
            }

            @Override
            public boolean validateRoleCertSanDnsName(String roleDomainName, String roleName,
                    String principalName, String dnsName, List<String> roleDnsSuffixList) {
                if (dnsName == null || roleDnsSuffixList == null) {
                    return false;
                }
                for (String suffix : roleDnsSuffixList) {
                    if (dnsName.endsWith(suffix)) {
                        return true;
                    }
                }
                return false;
            }
        };

        CertificateDataValidatorFactory factory = () -> validator;

        CertificateDataValidator testValidator = factory.create();
        assertNotNull(testValidator);

        assertTrue(testValidator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.athenz.io", "athenz.io", null));
        assertFalse(testValidator.validateServiceIdentityCertSanDnsName("sports", "api",
                "api.sports.invalid.io", "athenz.io", null));

        List<String> roleDnsSuffixList = Collections.singletonList("role.athenz.io");
        assertTrue(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", roleDnsSuffixList));
        assertFalse(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.invalid.io", roleDnsSuffixList));
        assertFalse(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", null, roleDnsSuffixList));
        assertFalse(testValidator.validateRoleCertSanDnsName("sports", "readers",
                "user.john", "john.user.role.athenz.io", null));
    }
}
