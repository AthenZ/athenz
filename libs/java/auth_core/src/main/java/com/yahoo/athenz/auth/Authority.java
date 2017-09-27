/**
 * Copyright 2016 Yahoo Inc.
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

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

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
    public void initialize();

    /**
     * @return credentials source - headers or certificate with headers being default
     */
    default public CredSource getCredSource() {
        return CredSource.HEADER;
    }

    /**
     * @return the domain of the authority, i.e. "user" or "local", as defined by the authorization system
     */
    public String getDomain();

    /**
     * @return a string describing where to find the credentials in a request, i.e. "X-Auth-Token" or "Cookie.User"
     */
    public String getHeader();

    /**
     * @return a boolean flag indicating whether or not authenticated principals
     * by this authority are allowed to be "authorized" to make changes. If this
     * flag is false, then the principal must first get a ZMS UserToken and then
     * use that UserToken for subsequent operations.
     */
    default public boolean allowAuthorization() {
        return true;
    }
    
    /**
     * If the authority is handling user principals, then it might require some
     * mapping from username to user domain name.
     * @param userName user name
     * @return mapped domain name
     */
    default public String getUserDomainName(String userName) {
        return userName;
    }
    
    /**
     * Verify the credentials and if valid return the corresponding Principal, null otherwise.
     * @param creds the credentials (i.e. cookie, token, secret) that will identify the principal.
     * @param remoteAddr remote IP address of the connection
     * @param httpMethod the http method for this request (e.g. GET, PUT, etc)
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the credentials, or null if the credentials are not valid.
     */
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg);
    
    /**
     * Process the client certificates extracted from the http request object.
     * Extract the CN field from the Certificate Subject DN which should be the Athenz
     * Service Identity and return a corresponding Principal object. In case any exceptions,
     * a null object is returned
     * @param certs an array of X509 certificates retrieved from the request
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the certificate, or null in case of failure.
     */
    default public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {
        return null;
    }
    
    /**
     * Process the authenticate request based on http request object.
     * @param request http servlet request
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the certificate, or null in case of failure.
     */
    default public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        return null;
    }
}
