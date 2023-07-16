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
package com.yahoo.athenz.auth.util;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.yahoo.athenz.auth.AuthorityConsts;

public class AthenzUtils {


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

        if (principal.contains(AuthorityConsts.ROLE_SEP)) {

            // it's a role certificate so we're going to extract
            // our service principal from the SAN uri or email field
            // first we're going to check the uri field

            principal = extractPrincipalFromUri(x509Cert);

            // if it's not available in the uri then we're going
            // to extract from the email san field

            if (principal == null) {
                principal = extractPrincipalFromEmail(x509Cert);
            }
        }

        return principal;
    }

    /**
     * Return the Athenz Service principal for the given role certificate.
     * If the certificate does not have the Athenz expected name format
     * the method will return null.
     * @param x509Cert x.509 role certificate
     * @return service principal name
     */
    public static String extractRolePrincipal(X509Certificate x509Cert) {

        // it's a role certificate, so we're going to extract
        // our service principal from the SAN uri or email field
        // first we're going to check the uri field

        String principal = extractPrincipalFromUri(x509Cert);

        // if it's not available in the uri then we're going
        // to extract from the email san field

        if (principal == null) {
            principal = extractPrincipalFromEmail(x509Cert);
        }

        return principal;
    }

    static String extractPrincipalFromEmail(X509Certificate x509Cert) {

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

        return email.substring(0, idx);
    }

    static String extractPrincipalFromUri(X509Certificate x509Cert) {

        final List<String> uris = Crypto.extractX509CertURIs(x509Cert);
        for (String uri : uris) {
            if (uri.startsWith(AuthorityConsts.ZTS_CERT_PRINCIPAL_URI)) {
                return uri.substring(AuthorityConsts.ZTS_CERT_PRINCIPAL_URI.length());
            }
        }

        return null;
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

        return principal.contains(AuthorityConsts.ROLE_SEP);
    }

    private static String extractNameFromArn(final String name, String separator) {
        int idx = name.indexOf(separator);
        if (idx == -1 || idx == 0 || idx == name.length() - separator.length()) {
            return null;
        } else {
            return name.substring(idx + separator.length());
        }
    }

    /**
     * Extract the role name from the full Athenz Role Name (arn)
     * which includes the domain name. The format of the role name
     * is {domain}:role.{role-name}
     * @param roleName the full arn of the role
     * @return role name, null if it's not expected full arn format
     */
    public static String extractRoleName(final String roleName) {
        return extractNameFromArn(roleName, AuthorityConsts.ROLE_SEP);
    }

    /**
     * Extract the policy name from the full Athenz policy Name (arn)
     * which includes the domain name. The format of the policy name
     * is {domain}:policy.{role-name}
     * @param policyName the full arn of the role
     * @return policy name, null if it's not expected full arn format
     */
    public static String extractPolicyName(final String policyName) {
        return extractNameFromArn(policyName, AuthorityConsts.POLICY_SEP);
    }

    /**
     * Extract the group name from the full Athenz Group Name (arn)
     * which includes the domain name. The format of the group name
     * is {domain}:group.{group-name}
     * @param groupName the full arn of the group
     * @return group name, null if it's not expected full arn format
     */
    public static String extractGroupName(final String groupName) {
        return extractNameFromArn(groupName, AuthorityConsts.GROUP_SEP);
    }
    /**
     * Extract the domain name from the full Athenz Role Name (arn)
     * which includes the role name. The format of the role name
     * is {domain}:role.{role-name}
     * @param roleName the full arn of the role
     * @return domain name, null if it's not expected full arn format
     */
    public static String extractRoleDomainName(final String roleName) {
        int idx = roleName.indexOf(AuthorityConsts.ROLE_SEP);
        if (idx == -1 || idx == 0 || idx == roleName.length() - AuthorityConsts.ROLE_SEP.length()) {
            return null;
        } else {
            return roleName.substring(0, idx);
        }
    }

    /**
     * Extract the domain name from the principal name which
     * is in the format {domain}.{service}
     * @param principalName full name of the principal
     * @return domain name, null if it's not the expected full principal service name
     */
    public static String extractPrincipalDomainName(final String principalName) {
        int idx = principalName.lastIndexOf(AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER_CHAR);
        if (idx == -1 || idx == 0 || idx == principalName.length() - 1) {
            return null;
        } else {
            return principalName.substring(0, idx);
        }
    }

    /**
     * Extract the service name from the principal name which
     * is in the format {domain}.{service}
     * @param principalName full name of the principal
     * @return service name, null if it's not the expected full principal service name
     */
    public static String extractPrincipalServiceName(final String principalName) {
        int idx = principalName.lastIndexOf(AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER_CHAR);
        if (idx == -1 || idx == 0 || idx == principalName.length() - 1) {
            return null;
        } else {
            return principalName.substring(idx + 1);
        }
    }

    /**
     * Split principal to domain and service, normalized to lower case
     * @param  name principal
     * @return      [domain, service], null if principal in invalid format
     */
    public static String[] splitPrincipalName(String name) {
        // all the role members in Athens are normalized to lower case
        String principalName = name.toLowerCase();
        int idx = principalName.lastIndexOf(AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER_CHAR);
        if (idx == -1 || idx == 0 || idx == principalName.length() - 1) {
            return null;
        }

        return new String[]{principalName.substring(0, idx), principalName.substring(idx + 1)};
    }

    /**
     * Join domain and service to principal format, normalized to lowercase
     * @param  domain  domain
     * @param  service service
     * @return principal (format: domain.service), null if domain or service is null or empty
     */
    public static String getPrincipalName(String domain, String service) {
        if (domain == null || service == null || domain.isEmpty() || service.isEmpty()) {
            return null;
        }
        return (domain + AuthorityConsts.ATHENZ_PRINCIPAL_DELIMITER + service).toLowerCase();
    }

    // prevent object creation
    private AthenzUtils() {
    }

    public static List<String> splitCommaSeparatedSystemProperty(String property) {
        String propertyListStr = System.getProperty(property, null);

        if (propertyListStr == null) {
            return new ArrayList<>();
        }

        return Stream.of(propertyListStr.trim().split("\\s*,\\s*")).collect(Collectors.toList());
    }
}
