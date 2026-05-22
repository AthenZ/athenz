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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.cert.CertificateDataValidator;
import com.yahoo.athenz.common.server.cert.CertificateDataValidatorFactory;

import java.util.List;

public class TestCertificateDataValidatorFactory implements CertificateDataValidatorFactory {

    @Override
    public CertificateDataValidator create() throws ServerResourceException {
        return new TestCertificateDataValidator();
    }

    public static final class FactoryThrowsException implements CertificateDataValidatorFactory {

        @Override
        public CertificateDataValidator create() throws ServerResourceException {
            throw new ServerResourceException(500, "factory failure");
        }
    }

    public static final class TestCertificateDataValidator implements CertificateDataValidator {

        @Override
        public boolean validateServiceIdentityCertSanDnsName(String domainName, String serviceName,
                String dnsName, String serviceDnsSuffix, List<String> providerDnsSuffixes) {
            return true;
        }

        @Override
        public boolean validateRoleCertSanDnsName(String roleDomainName, String roleName,
                String principalName, String dnsName, List<String> roleDnsSuffixList) {
            return true;
        }
    }
}
