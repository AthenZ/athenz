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
import com.yahoo.athenz.common.server.cert.X509CertEmailValidatorFactory;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultX509CertEmailValidatorFactory implements X509CertEmailValidatorFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultX509CertEmailValidatorFactory.class);

    private static final String X509_CERT_EMAIL_VALIDATOR_REJECT_EMAILS_PROPERTY =
            "athenz.zts.x509_cert_email_validator_reject_emails";

    @Override
    public X509CertEmailValidator create() throws ServerResourceException {

        // Check if we should reject emails or just log them
        // Default is false (just log them)

        boolean rejectEmails = Boolean.parseBoolean(
                System.getProperty(X509_CERT_EMAIL_VALIDATOR_REJECT_EMAILS_PROPERTY, "false"));

        LOGGER.info("Creating DefaultX509CertEmailValidator with rejectEmails={}", rejectEmails);

        return new DefaultX509CertEmailValidator(rejectEmails);
    }
}
