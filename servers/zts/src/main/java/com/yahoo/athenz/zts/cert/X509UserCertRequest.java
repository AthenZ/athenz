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
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class X509UserCertRequest extends X509CertRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509UserCertRequest.class);

    protected String reqUserName;
    protected String userPrincipal;

    public X509UserCertRequest(String csr, SpiffeUriManager spiffeUriManager) throws CryptoException {
        super(csr, spiffeUriManager);
    }

    public boolean validate(final String domainName, final String userName, final Set<String> validCertSubjectOrgValues) {

        // the csr must not have any dns names 

        if (!dnsNames.isEmpty()) {
            LOGGER.error("DNS names are not allowed in the User CSR");
            return false;
        }

        // the csr must not have any ip addresses

        if (!ipAddresses.isEmpty()) {
            LOGGER.error("IP addresses are not allowed in the User CSR");
            return false;
        }

        // the instnace id and uri hostname must be null

        if (instanceId != null || uriHostname != null) {
            LOGGER.error("Instance ID and URI hostname must be null in the User CSR");
            return false;
        }

        // uri list must be empty or have a single spiffe uri

        if (uris.size() > 1 || (uris.size() == 1 && spiffeUri == null)) {
            LOGGER.error("User CSR must have a single SPIFFE URI, found: {}", uris.size());
            return false;
        }

        // validate the o field value is specified

        if (!validateSubjectOField(validCertSubjectOrgValues)) {
            return false;
        }

        // validate spiffe uri if one is provided

        return validateSpiffeURI(domainName, userName);
    }

    public boolean validateSpiffeURI(final String domainName, final String userName) {

        // validate the spiffe uri according to our configured validators

        if (spiffeUri == null) {
            return true;
        }

        return spiffeUriManager.validateServiceCertUri(spiffeUri, domainName, userName,
             spiffeUriManager.getDefaultUserNamespace());
    }
}
