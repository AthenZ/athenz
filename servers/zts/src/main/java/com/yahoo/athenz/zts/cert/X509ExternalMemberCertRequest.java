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

import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.cert.CertificateDataValidator;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public class X509ExternalMemberCertRequest extends X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509ExternalMemberCertRequest.class);

    public X509ExternalMemberCertRequest(String csr, SpiffeUriManager spiffeUriManager,
            CertificateDataValidator certificateDataValidator) throws CryptoException {
        super(csr, spiffeUriManager, certificateDataValidator);
    }

    public boolean validate(final Set<String> validCertSubjectOrgValues) {

        if (!dnsNames.isEmpty()) {
            LOGGER.error("DNS names are not allowed in the External Member CSR");
            return false;
        }

        if (!ipAddresses.isEmpty()) {
            LOGGER.error("IP addresses are not allowed in the External Member CSR");
            return false;
        }

        if (instanceId != null || uriHostname != null) {
            LOGGER.error("Instance ID and URI hostname must be null in the External Member CSR");
            return false;
        }

        if (!uris.isEmpty()) {
            LOGGER.error("URIs are not allowed in the External Member CSR");
            return false;
        }

        return validateSubjectOField(validCertSubjectOrgValues);
    }
}
