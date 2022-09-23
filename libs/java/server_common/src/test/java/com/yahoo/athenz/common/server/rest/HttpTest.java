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

import jakarta.servlet.http.HttpServletRequest;

import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.mockito.Mockito.times;
import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authority.CredSource;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

public class HttpTest {

    @Test
    public void testAuthoritiesNotNull() {
        Http.AuthorityList authorities = new Http.AuthorityList();
        assertNotNull(authorities.getAuthorities());
    }

    @Test
    public void testAuthenticateInternalServerError() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        try {
            Http.authenticate(httpServletRequest, null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 500);
        }
    }

    @Test
    public void testAuthenticateCertificateFailure() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.CERTIFICATE);
        authorities.add(authority);
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthenticateCertificate() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.CERTIFICATE);
        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = Mockito.mock(X509Certificate.class);
        Mockito.when(httpServletRequest.getAttribute(Http.JAVAX_CERT_ATTR)).thenReturn(certs);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authority.authenticate(ArgumentMatchers.any(X509Certificate[].class),
                ArgumentMatchers.any())).thenReturn(principal);
        authorities.add(authority);
        assertNotNull(Http.authenticate(httpServletRequest, authorities));
    }

    @Test
    public void testAuthenticateRequest() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.REQUEST);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(authority.authenticate(ArgumentMatchers.any(HttpServletRequest.class),
                ArgumentMatchers.any())).thenReturn(principal);
        authorities.add(authority);
        assertNotNull(Http.authenticate(httpServletRequest, authorities));
    }

    @Test
    public void testAuthenticateHeaderFailure() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn("Cookie.hogehoge");
        Mockito.when(authority.getAuthenticateChallenge()).thenReturn("Basic realm=\"athenz\"");
        authorities.add(authority);
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
        Set<String> challenges = new HashSet<>();
        challenges.add("Basic realm=\"athenz\"");
        Mockito.verify(httpServletRequest, times(1))
                .setAttribute("com.yahoo.athenz.auth.credential.challenges", challenges);
    }

    @Test
    public void testAuthenticateHeaderErrorMessage() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getHeader("Athenz-Principal-Auth")).thenReturn("Creds");
        Http.AuthorityList authorities = new Http.AuthorityList();
        PrincipalAuthority authority1 = new PrincipalAuthority();
        authorities.add(authority1);
        PrincipalAuthority authority2 = new PrincipalAuthority();
        authorities.add(authority2);
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
        Mockito.verify(httpServletRequest, times(1))
                .setAttribute(ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
        Mockito.verify(httpServletRequest, times(1))
                .setAttribute(ArgumentMatchers.anyString(), ArgumentMatchers.anyIterable());
    }

    @Test
    public void testAuthenticateHeaderFailureMultipleAuth() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority1 = Mockito.mock(Authority.class);
        Mockito.when(authority1.getCredSource()).thenReturn(CredSource.HEADER);
        Mockito.when(authority1.getHeader()).thenReturn("Cookie.hogehoge");
        Mockito.when(authority1.getAuthenticateChallenge()).thenReturn("Basic realm=\"athenz\"");
        authorities.add(authority1);
        Authority authority2 = Mockito.mock(Authority.class);
        Mockito.when(authority2.getCredSource()).thenReturn(CredSource.REQUEST);
        Mockito.when(authority2.getAuthenticateChallenge()).thenReturn("AthenzRequest realm=\"athenz\"");
        authorities.add(authority2);
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
        Set<String> challenges = new HashSet<>();
        challenges.add("Basic realm=\"athenz\"");
        challenges.add("AthenzRequest realm=\"athenz\"");
        Mockito.verify(httpServletRequest, times(1))
                .setAttribute("com.yahoo.athenz.auth.credential.challenges", challenges);
    }

    @Test
    public void testAuthenticateHeaderNull() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn(null);
        // we should not get npe - instead standard 401
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthenticatedUserInvalidCredentials() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        try {
            Http.authenticatedUser(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthenticatedUser() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getFullName()).thenReturn("athenz.api");
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn("Athenz-Principal-Auth");
        Mockito.when(httpServletRequest.getHeader("Athenz-Principal-Auth")).thenReturn("Creds");
        Mockito.when(authority.authenticate(ArgumentMatchers.any(), ArgumentMatchers.any(),
                ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn(principal);
        Http.AuthorityList authorities = new Http.AuthorityList();
        authorities.add(authority);

        assertEquals(Http.authenticatedUser(httpServletRequest, authorities), "athenz.api");
    }

    @Test
    public void testAuthorizedUserUserInvalidCredentials() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        try {
            Http.authorizedUser(httpServletRequest, authorities, authorizer, "action", null, null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthorizedUser() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getFullName()).thenReturn("athenz.api");
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Mockito.when(authorizer.access(ArgumentMatchers.any(), ArgumentMatchers.any(),
                ArgumentMatchers.any(Principal.class), ArgumentMatchers.any())).thenReturn(true);
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn("Athenz-Principal-Auth");
        Mockito.when(httpServletRequest.getHeader("Athenz-Principal-Auth")).thenReturn("Creds");
        Mockito.when(authority.authenticate(ArgumentMatchers.any(), ArgumentMatchers.any(),
                ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn(principal);
        Http.AuthorityList authorities = new Http.AuthorityList();
        authorities.add(authority);

        assertEquals("athenz.api", Http.authorizedUser(httpServletRequest, authorities, authorizer, "action", "resource", null));
    }

    @Test
    public void testAuthorizedBadRequest() {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(authorizer, principal, "action", null, null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 400);
        }
    }

    @Test
    public void testAuthorizedInternalServerError() {
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(null, principal, "action", "resource", null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 500);
        }
    }

    @Test
    public void testAuthorizedForbidden() {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(authorizer, principal, "action", "resource", null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 403);
            assertEquals(expected.getMessage(), "ResourceException (403): Forbidden");
        }
    }

    @Test
    public void testAuthorizedForbiddenMtlsRestricted() {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getMtlsRestricted()).thenReturn(true);
        try {
            Http.authorize(authorizer, principal, "action", "resource", null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 403);
            assertEquals(expected.getMessage(), "ResourceException (403): mTLS Restricted");
        }
    }

    @Test
    public void testGetCookieValue() {

        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getCookies()).thenReturn(null);

        assertNull(Http.getCookieValue(httpServletRequest, "cookie1"));
        assertNull(Http.getCookieValue(httpServletRequest, "cookie2"));

        jakarta.servlet.http.Cookie[] cookies = new jakarta.servlet.http.Cookie[2];
        cookies[0] = new jakarta.servlet.http.Cookie("cookie1", "value1");
        cookies[1] = new jakarta.servlet.http.Cookie("cookie2", "value2");

        Mockito.when(httpServletRequest.getCookies()).thenReturn(cookies);
        assertEquals(Http.getCookieValue(httpServletRequest, "cookie1"), "value1");
        assertEquals(Http.getCookieValue(httpServletRequest, "cookie2"), "value2");
        assertNull(Http.getCookieValue(httpServletRequest, "cookie3"));
    }

    @Test
    public void testAuthenticatingCredentialsHeaderNull() {
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getHeader()).thenReturn(null);
        assertNull(Http.authenticatingCredentials(null, authority));
    }
}
