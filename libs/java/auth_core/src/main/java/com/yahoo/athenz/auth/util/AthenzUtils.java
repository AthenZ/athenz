/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.auth.util;

import java.security.cert.X509Certificate;
import java.util.List;

public class AthenzUtils {

    private final static String ROLE_SEP = ":role.";

    /**
     * Return the Athenz Service principal for the given certificate which
     * could be either a service certificate or a role certificate.
     * If the certificate does not have the Athenz expected name format
     * the method will return null.
     * @param x509Cert x.509 athenz service or role certificate
     * @return service principal cn
     */
    public static String extractServicePrincipal(X509Certificate x509Cert) {

        // let's first get the common name of the certificate

        String principal = Crypto.extractX509CertCommonName(x509Cert);
        if (principal == null) {
            return null;
        }

        // check to see if we're dealing with role certificate which
        // has the <domain>:role.<rolename> format or service
        // certificate which has the <domain>.<service> format

        if (principal.contains(ROLE_SEP)) {

            // it's a role certificate so we're going to extract
            // our service principal from the SAN email fieid
            // verify that we must have only a single email
            // field in the certificate

            final List<String> emails = Crypto.extractX509CertEmails(x509Cert);
            if (emails.size() != 1) {
                return null;
            }

            // athenz always verifies that we include a valid
            // email in the certificate

            final String email = emails.get(0);
            int idx = email.indexOf('@');
            if (idx == -1) {
                return null;
            }

            principal = email.substring(0, idx);
        }

        return principal;
    }

    /**
     * Return if the given x.509 certificate is a role certificate or not
     * @param x509Cert x.509 athenz service or role certificate
     * @return true if role certificate, false if service identity certificate
     */
    public static boolean isRoleCertificate(X509Certificate x509Cert) {

        // let's first get the common name of the certificate

        final String principal = Crypto.extractX509CertCommonName(x509Cert);
        if (principal == null) {
            return false;
        }

        // check to see if we're dealing with role certificate which
        // has the <domain>:role.<rolename> format or service
        // certificate which has the <domain>.<service> format

        return principal.contains(ROLE_SEP);
    }
}
