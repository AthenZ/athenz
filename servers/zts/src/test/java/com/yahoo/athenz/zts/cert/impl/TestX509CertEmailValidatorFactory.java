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
import com.yahoo.athenz.common.server.cert.X509CertEmailValidator;
import com.yahoo.athenz.common.server.cert.X509CertEmailValidatorFactory;

import java.util.List;

public class TestX509CertEmailValidatorFactory implements X509CertEmailValidatorFactory {

    @Override
    public X509CertEmailValidator create() throws ServerResourceException {
        return new TestX509CertEmailValidator();
    }

    public static final class FactoryThrowsException implements X509CertEmailValidatorFactory {

        @Override
        public X509CertEmailValidator create() throws ServerResourceException {
            throw new ServerResourceException(500, "factory failure");
        }
    }

    public static final class TestX509CertEmailValidator implements X509CertEmailValidator {

        @Override
        public boolean validateServiceCertificateEmails(String domainName, String serviceName, List<String> emails) {
            return true;
        }
    }
}
