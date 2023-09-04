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

import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.security.cert.X509Certificate;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;

public class Http {

    private static final Logger LOG = LoggerFactory.getLogger(Http.class);

    public static final String WWW_AUTHENTICATE  = "WWW-Authenticate";
    public static final String INVALID_CRED_ATTR = "com.yahoo.athenz.auth.credential.error";
    public static final String AUTH_CHALLENGES   = "com.yahoo.athenz.auth.credential.challenges";
    public static final String JAVAX_CERT_ATTR   = "jakarta.servlet.request.X509Certificate";

    public static class AuthorityList {
        List<Authority> authorities;

        public AuthorityList() {
            authorities = new ArrayList<>();
        }

        public void add(Authority a) {
            authorities.add(a);
        }
        
        public List<Authority> getAuthorities() {
            return authorities;
        }
    }
    
    static String getCookieValue(HttpServletRequest hreq, String name) {

        jakarta.servlet.http.Cookie[] cookies = hreq.getCookies();
        if (cookies == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    static String authenticatingCredentials(HttpServletRequest request,
            Authority authority) {
        final String header = authority.getHeader();
        if (header == null) {
            return null;
        }
        return header.startsWith("Cookie.") ? getCookieValue(request,
                header.substring(7)) : request.getHeader(header);
    }

    public static Principal authenticate(HttpServletRequest request,
            AuthorityList authorities) {
        return authenticate(request, authorities, false);
    }

    public static Principal authenticate(HttpServletRequest request,
            AuthorityList authorities, boolean optionalAuth) {

        if (authorities == null) {
            LOG.error("authenticate: No authorities configured");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No authorities configured");
        }

        StringBuilder authErrMsg = new StringBuilder(512);
        Set<String> authChallenges = null;
        for (Authority authority : authorities.authorities) {
            Principal principal = null;
            StringBuilder errMsg = new StringBuilder(512);
            switch (authority.getCredSource()) {
            case HEADER:
                String creds = authenticatingCredentials(request, authority);

                if (creds != null) {
                    principal = authority.authenticate(creds, ServletRequestUtil.getRemoteAddress(request),
                            request.getMethod(), errMsg);
                }
                break;
            case CERTIFICATE:
                X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
                if (certs != null && certs[0] != null) {
                    principal = authority.authenticate(certs, errMsg);
                }
                break;
            case REQUEST:
                principal = authority.authenticate(request, errMsg);
                break;
            }
            
            // if we got a valid principal then we're done with our
            // authentication process and we'll return right away
            
            if (principal != null) {
                return principal;
            }

            final String challenge = authority.getAuthenticateChallenge();
            if (challenge != null) {
                if (authChallenges == null) {
                    authChallenges = new HashSet<>();
                }
                authChallenges.add(challenge);
            }

            // otherwise if we have a specific error message from an authority
            // then we'll keep it in case all other authorities also fail and
            // we need to log the reason for failure
            
            if (errMsg.length() > 0) {
                authErrMsg.append(":error: ").append(errMsg);
            }
        }

        // if we were not given any credentials - i.e. our authErrMsg is
        // empty and the optional auth flag is true then we'll just return
        // a null principal instead of any exceptions

        if (authErrMsg.length() == 0 && optionalAuth) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("authenticate: No credentials provided for optional auth request");
            }
            return null;
        }

        // set the error message as a request attribute - if our error string
        // is empty then we had no credentials provided
        
        if (authErrMsg.length() > 0) {
            request.setAttribute(INVALID_CRED_ATTR, authErrMsg.toString());
            LOG.error("authenticate: {}", authErrMsg);
        } else {
            request.setAttribute(INVALID_CRED_ATTR, "No credentials provided");
            LOG.error("authenticate: No credentials provided");
        }

        // if we have challenges specified, we're going to set it as a request
        // attribute and let the caller decide if they want to add it to the
        // response as a header in its context handler

        request.setAttribute(AUTH_CHALLENGES, authChallenges);
        throw new ResourceException(ResourceException.UNAUTHORIZED, "Invalid credentials");
    }

    public static String authenticatedUser(HttpServletRequest request,
            AuthorityList authorities) {
        Principal principal = authenticate(request, authorities);
        return principal.getFullName();
    }

    public static String authorizedUser(HttpServletRequest request,
            AuthorityList authorities, Authorizer authorizer, String action,
            String resource, String otherDomain) {
        Principal principal = authenticate(request, authorities);
        authorize(authorizer, principal, action, resource, otherDomain);
        return principal.getFullName();
    }

    public static Principal authorize(Authorizer authorizer, Principal principal,
            String action, String resource, String otherDomain) {
        
        if (action == null || resource == null) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Missing 'action' and/or 'resource' parameters");
        }
        if (principal.getMtlsRestricted()) {
            throw new ResourceException(ResourceException.FORBIDDEN, "mTLS Restricted");
        }
        if (authorizer != null) {
            if (!authorizer.access(action, resource, principal, otherDomain)) {
                throw new ResourceException(ResourceException.FORBIDDEN, "Forbidden");
            }
        } else {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No authorizer configured in service");
        }
        return principal;
    }
}
