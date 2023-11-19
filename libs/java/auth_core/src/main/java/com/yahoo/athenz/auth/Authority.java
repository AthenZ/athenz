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
package com.yahoo.athenz.auth;

import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * An Authority can validate credentials of a Principal in its domain. It also can provide HTTP header information
 * that determines where to find relevant credentials for that task.
 */
public interface Authority {

    /**
     * Source for the credentials - either headers or certificate
     */
    enum CredSource {
        HEADER,
        CERTIFICATE,
        REQUEST
    }

    /**
     * Initialize the authority
     */
    void initialize();

    /**
     * @return the string to be included as the identifier for the
     *  authority which will be logged in the server access log file
     *  as the last field so we know what authority was responsible
     *  for authenticating the principal.
     */
    default String getID() {
        return "Auth-ID";
    }

    /**
     * @return credentials source - headers or certificate with headers being default
     */
    default CredSource getCredSource() {
        return CredSource.HEADER;
    }

    /**
     * @return the domain of the authority, i.e. "user" or "local", as defined by the authorization system
     */
    String getDomain();

    /**
     * @return a string describing where to find the credentials in a request, i.e. "X-Auth-Token" or "Cookie.User"
     */
    String getHeader();

    /**
     * @return the string to be returned as the value for WWW-Authenticate header:
     *        WWW-Authenticate  = "WWW-Authenticate" ":" 1#challenge
     * in case all authorities fail to authenticate a request.
     */
    default String getAuthenticateChallenge() {
        return null;
    }

    /**
     * @return a boolean flag indicating whether or not authenticated principals
     * by this authority are allowed to be "authorized" to make changes. If this
     * flag is false, then the principal must first get a ZMS UserToken and then
     * use that UserToken for subsequent operations.
     */
    default boolean allowAuthorization() {
        return true;
    }

    /**
     * If the authority is handling user principals, then it might require some
     * mapping from username to user domain name.
     * @param userName user name
     * @return mapped domain name
     */
    default String getUserDomainName(String userName) {
        return userName;
    }

    /**
     * If the authority is handling user principals, then this method will be
     * called when users are added as members so the authority can validate
     * that the role member is valid. If the member is not valid, the request
     * (e.g. putRole, putMembership) will be rejected as invalid.
     * @param username name of the user to check
     * @return true if username is valid, false otherwise
     */
    default boolean isValidUser(String username) {
        return true;
    }

    /**
     * Verify the credentials and if valid return the corresponding Principal, null otherwise.
     * @param creds the credentials (i.e. cookie, token, secret) that will identify the principal.
     * @param remoteAddr remote IP address of the connection
     * @param httpMethod the http method for this request (e.g. GET, PUT, etc)
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the credentials, or null if the credentials are not valid.
     */
    Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg);

    /**
     * Process the client certificates extracted from the http request object.
     * Extract the CN field from the Certificate Subject DN which should be the Athenz
     * Service Identity and return a corresponding Principal object. In case any exceptions,
     * a null object is returned
     * @param certs an array of X509 certificates retrieved from the request
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the certificate, or null in case of failure.
     */
    default Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {
        return null;
    }

    /**
     * Process the authenticate request based on http request object.
     * @param request http servlet request
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the certificate, or null in case of failure.
     */
    default Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        return null;
    }

    /**
     * Return the requested boolean attribute state from the user authority
     * @param username user's name or id
     * @param attribute boolean attribute name
     * @return true if the given attribute is enabled for the user
     */
    default boolean isAttributeSet(final String username, final String attribute) {
        return false;
    }

    /**
     * Set of valid boolean attributes supported by the authority
     * @return Set of attribute names, empty set if none are supported
     */

    default Set<String> booleanAttributesSupported() {
        return Collections.emptySet();
    }

    /**
     * Return the requested date attribute state from the user authority
     * @param username user's name or id
     * @param attribute date attribute name
     * @return configured date or null if one is not configured
     */
    default Date getDateAttribute(final String username, final String attribute) {
        return null;
    }

    /**
     * Set of valid date attributes supported by the authority
     * @return Set of attribute names, empty set if none are supported
     */

    default Set<String> dateAttributesSupported() {
        return Collections.emptySet();
    }

    /**
     * Return user's registered email address
     * @param username user's name or id
     * @return user's registered email or null if not available
     */
    default String getUserEmail(final String username) {
        return null;
    }

    /**
     * Retrieves a list of principals based on the state parameter from configured Principal Authority and
     * uses that data to modify role and group memberships
     * @param principalStates EnumSet containing expected state(s) of principals
     * @return List of Principal or an empty collection if none
     */
    default List<Principal> getPrincipals(EnumSet<Principal.State> principalStates) {
        return Collections.emptyList();
    }

    /**
     * Retrieves the principal's manager's username. This is used for domain contacts
     * when a domain contact user is no longer valid, the server will automatically
     * assign the contact type to the user's manager.
     * @param username user's name or id
     * @return user's manager's name or id
     */
    default String getUserManager(final String username) {
        return null;
    }
}
