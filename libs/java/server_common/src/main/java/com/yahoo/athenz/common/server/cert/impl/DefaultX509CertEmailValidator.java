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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DefaultX509CertEmailValidator implements X509CertEmailValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultX509CertEmailValidator.class);

    private final boolean rejectEmails;

    public DefaultX509CertEmailValidator(boolean rejectEmails) {
        this.rejectEmails = rejectEmails;
    }

    @Override
    public boolean validateServiceCertificateEmails(String domainName, String serviceName, List<String> emails) {

        // if we have no email addresses in the CSR then we're good

        if (emails == null || emails.isEmpty()) {
            return true;
        }

        // log all email addresses found in the CSR for service certificate

        for (String email : emails) {
            LOGGER.error("Service certificate request for {}.{} contains email address: {}", domainName, serviceName, email);
        }

        // reject if configured to do so, otherwise just log and allow

        return !rejectEmails;
    }
}
