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
package com.yahoo.athenz.common.server.rest;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

import java.util.Set;

public class ResourceContext  {

    private static boolean SEND_MULTIPLE_WWW_AUTHENTICATE_HEADERS = Boolean.parseBoolean(
            System.getProperty("athenz.http.www-authenticate.multiple-headers", "true"));

    private final ServletContext servletContext;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final Http.AuthorityList authorities;
    private final Authorizer authorizer;

    protected Principal principal;
    protected boolean checked;
    private String requestDomain;

    public ResourceContext(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response,
            Http.AuthorityList authorities, Authorizer authorizer) {
        this.servletContext = servletContext;
        this.request = request;
        this.response = response;
        this.authorities = authorities;
        this.authorizer = authorizer;
        this.principal = null;
        this.checked = false;
    }

    /**
     * Configure server to return multiple WWW-Authenticate headers in the response
     * corresponding to each authority configured.
     * @param bSendMultipleHeaders boolean flag indicating support for multiple headers
     */
    public static void setSendMultipleWwwAuthenticateHeaders(boolean bSendMultipleHeaders) {
        SEND_MULTIPLE_WWW_AUTHENTICATE_HEADERS = bSendMultipleHeaders;
    }

    /**
     * Return the servlet context object
     * @return ServletContext object
     */
    public ServletContext servletContext() {
        return servletContext;
    }

    /**
     * Return the http servlet request object
     * @return HttpServletRequest object
     */
    public HttpServletRequest request() {
        return request;
    }

    /**
     * Return the http servlet response object
     * @return HttpServletResponse object
     */
    public HttpServletResponse response() {
        return response;
    }

    /**
     * Return the principal object. can be null if the request is not authenticated
     * @return Principal object
     */
    public Principal principal() {
        return principal;
    }

    /**
     * Authenticates the request based on configured set of
     * authorities. It throws an exception if it cannot
     * authenticate
     * @return Principal object
     */
    public Principal authenticate() {
        return authenticate(false);
    }

    /**
     * Authenticates the request based on configured set of
     * authorities. It throws an exception if it cannot
     * authenticate unless there are no credentials provided
     * and optionalAuth flag is set
     * @param optionalAuth authentication is optional
     * @return Principal object, could be null
     */
    public Principal authenticate(boolean optionalAuth) {
        if (!checked) {
            checked = true;
            principal = Http.authenticate(request, authorities, optionalAuth);
        }
        return principal;
    }

    /**
     * It authenticates and then authorizes the request for
     * a given action, resource and trust domain.
     * It throws an authorized exception if it cannot
     * authenticate and a forbidden exception if it cannot
     * authorize
     * @param action for the authorization check
     * @param resource for the authorization check
     * @param trustedDomain for the authorization check
     */
    public void authorize(String action, String resource, String trustedDomain) {
        principal = authenticate();
        Http.authorize(authorizer, principal, action, resource, trustedDomain);
    }

    /**
     * If requested include the WWW-Authenticate challenge response
     * header for this request. This is only done if the exception
     * was thrown for invalid credentials.
     * @param exc ResourceException that was thrown when calling authenticate
     */
    public void sendAuthenticateChallenges(ResourceException exc) {

        // first check to see if this is an auth failure and if
        // that's the case include the WWW-Authenticate challenge

        if (exc.getCode() != ResourceException.UNAUTHORIZED) {
            return;
        }

        Set<String> authChallenges = (Set<String>) request.getAttribute(Http.AUTH_CHALLENGES);
        if (authChallenges == null) {
            return;
        }

        // check if we're going to return multiple WWW-Authenticate headers
        // or combine them into a single comma separated value
        // One issue: with Kerberos curl supports auto negotiate only
        // the value is passed in a separate header

        if (SEND_MULTIPLE_WWW_AUTHENTICATE_HEADERS) {
            for (String challenge : authChallenges) {
                response.addHeader(Http.WWW_AUTHENTICATE, challenge);
            }
        } else {
            response.addHeader(Http.WWW_AUTHENTICATE, String.join(", ", authChallenges));
        }
    }

    /**
     * Return the request domain name if one was set, null otherwise.
     * @return request domain name
     */
    public String getRequestDomain() {
        return requestDomain;
    }

    /**
     * Set the request domain name for the resource
     * @param requestDomain request domain name
     */
    public void setRequestDomain(String requestDomain) {
        this.requestDomain = requestDomain;
    }
}
