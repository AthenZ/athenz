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
package com.yahoo.athenz.common.server.rest;

import java.util.List;
import java.util.ArrayList;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

public class Http {

    public static final String INVALID_CRED_ATTR = "com.yahoo.athenz.auth.credential.error";
    public static final String LOOPBACK_ADDRESS  = "127.0.0.1";
    public static final String XFF_HEADER        = "X-Forwarded-For";
    public static final String JAVAX_CERT_ATTR   = "javax.servlet.request.X509Certificate";
    
    public static class AuthorityList {
        List<Authority> authorities;

        public AuthorityList() {
            authorities = new ArrayList<Authority>();
        }

        public void add(Authority a) {
            authorities.add(a);
        }
        
        public List<Authority> getAuthorities() {
            return authorities;
        }
    }
    
    static String getCookieValue(HttpServletRequest hreq, String name) {
        
        javax.servlet.http.Cookie[] cookies = hreq.getCookies();
        if (cookies == null) {
            return null;
        }
        for (javax.servlet.http.Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static String authenticatingCredentials(HttpServletRequest request,
            Authority authority) {
        String header = authority.getHeader();
        String creds = header.startsWith("Cookie.") ? getCookieValue(request,
                header.substring(7)) : request.getHeader(header);
        return creds;
    }

    public static String authenticatingCredentials(HttpServletRequest request,
            AuthorityList authorities) {
        if (authorities == null) {
            return null;
        }
        for (Authority authority : authorities.authorities) {
            String creds = authenticatingCredentials(request, authority);
            if (creds != null) {
                return creds;
            }
        }
        return null;
    }

    /**
      * Return the remote client IP address.
      * Detect if connection is from ATS by looking at XFF header.
      * If XFF header, return the last address therein since it was added by ATS.
     **/
    static String getRemoteAddress(final HttpServletRequest request) {
        String addr = request.getRemoteAddr();
        if (addr.equals(LOOPBACK_ADDRESS)) {
            String xff = request.getHeader(XFF_HEADER);
            if (xff != null) {
                String[] addrs = xff.split(",");
                addr = addrs[addrs.length - 1].trim();
            }
        }
        return addr;
    }
    
    public static Principal authenticate(HttpServletRequest request,
            AuthorityList authorities) {
        if (authorities == null) {
            throw new ResourceException (ResourceException.INTERNAL_SERVER_ERROR,
                    "No authorities configured");
        }

        StringBuilder authErrMsg = new StringBuilder(512);
        for (Authority authority : authorities.authorities) {
            Principal principal = null;
            StringBuilder errMsg = new StringBuilder(512);
            switch (authority.getCredSource()) {
            case HEADER:
                String creds = authenticatingCredentials(request, authority);
                if (creds != null) {
                    principal = authority.authenticate(creds, getRemoteAddress(request), request.getMethod(), errMsg);
                }
                break;
            case CERTIFICATE:
                X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
                if (certs != null) {
                    principal = authority.authenticate(certs, errMsg);
                }
                break;
            }
            
            if (principal != null) {
                return principal;
            } else {
                authErrMsg.append(":error: ").append(errMsg);
            }
        }
        // set the error message as a request attribute
        request.setAttribute(INVALID_CRED_ATTR, authErrMsg.toString());
        throw new ResourceException (ResourceException.UNAUTHORIZED, "Invalid credentials");
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
        if (principal == null) {
            return null;
        }
        return principal.getFullName();
    }

    public static Principal authorize(Authorizer authorizer, Principal principal,
            String action, String resource, String otherDomain) {
        
        if (action == null || resource == null) {
            throw new ResourceException(ResourceException.BAD_REQUEST,
                    "Missing 'action' and/or 'resource' pararameters");
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
