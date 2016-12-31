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

import javax.servlet.http.HttpServletRequest;

import org.mockito.Mockito;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authority.CredSource;

public class HttpTest {

    @Test
    public void testAuthenticatingCredentialsNull() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        assertNull(Http.authenticatingCredentials(httpServletRequest, null));
    }

    @Test
    public void testAuthenticatingCredentials() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getHeader()).thenReturn("hogehoge");
        authorities.add(authority);
        assertNull(Http.authenticatingCredentials(httpServletRequest, authorities));
    }

    @Test
    public void testAuthoritiesNotNull() {
        Http.AuthorityList authorities = new Http.AuthorityList();
        assertNotNull(authorities.getAuthorities());
    }

    @Test
    public void testAuthenticateInternalServerError() throws Exception {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        try {
            Http.authenticate(httpServletRequest, null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 500);
        }
    }

    @Test
    public void testAuthenticateCertificate() throws Exception {
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
    public void testAuthenticateHeader() throws Exception {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn("Cookie.hogehoge");
        authorities.add(authority);
        try {
            Http.authenticate(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }
    
    @Test
    public void testAuthenticatedUserInvalidCredentials() throws Exception {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        try {
            Http.authenticatedUser(httpServletRequest, authorities);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthorizedUserUserInvalidCredentials() throws Exception {
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
    public void testAuthorizedBadRequest() throws Exception {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(authorizer, principal, "action", null, null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 400);
        }
    }

    @Test
    public void testAuthorizedInternalServerError() throws Exception {
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(null, principal, "action", "resource", null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 500);
        }
    }

    @Test
    public void testAuthorizedForbidden() throws Exception {
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = Mockito.mock(Principal.class);
        try {
            Http.authorize(authorizer, principal, "action", "resource", null);
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 403);
        }
    }
}
