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

import com.yahoo.athenz.auth.ExternalMemberValidator;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A sample external member validator that validates email addresses.
 * It doesn't verify the strict rules for email addresses (for example,
 * it can't contain consecutive dots, etc), but it can be used for 
 * simple email address validation.
 *
 * The validator can be configured with a list of email domains that are
 * allowed to be used as external members. The list of domains can be
 * configured with the system property "athenz.external_member.valid_email_domains".
 * The list of domains should be a comma-separated list of email domains.
 * The domains are case-insensitive.
 *
 * For example, to allow only email addresses with domains "example.com" and "corp.net",
 * the system property can be set to:
 *
 * athenz.external_member.valid_email_domains=example.com,corp.net
 *
 * The validator will then only allow email addresses with domains "example.com" or "corp.net".
 *
 */
public class ExternalEmailMemberValidator implements ExternalMemberValidator {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalEmailMemberValidator.class);

    public static final String PROP_VALID_EMAIL_DOMAINS = "athenz.external_member.valid_email_domains";

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    private final Set<String> validEmailDomains;


    public ExternalEmailMemberValidator() {
        validEmailDomains = parseEmailDomains(System.getProperty(PROP_VALID_EMAIL_DOMAINS));
    }

    static Set<String> parseEmailDomains(final String domainList) {
        if (domainList == null || domainList.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> domains = new HashSet<>();
        for (String domain : domainList.split(",")) {
            final String trimmed = domain.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                domains.add(trimmed);
            }
        }
        return Collections.unmodifiableSet(domains);
    }

    @Override
    public boolean validateMember(final String domainName, final String memberName) {

        if (memberName == null || memberName.isEmpty()) {
            LOG.error("Member name is null or empty");
            return false;
        }

        if (!EMAIL_PATTERN.matcher(memberName).matches()) {
            LOG.error("Member name is not a valid email address: {}", memberName);
            return false;
        }

        if (validEmailDomains.isEmpty()) {
            return true;
        }

        final String emailDomain = memberName.substring(memberName.indexOf('@') + 1).toLowerCase();
        return validEmailDomains.contains(emailDomain);
    }

    Set<String> getValidEmailDomains() {
        return validEmailDomains;
    }
}
