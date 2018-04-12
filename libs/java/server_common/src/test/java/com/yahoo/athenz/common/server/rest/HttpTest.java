/*
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
    public void testAuthenticateCertificate() {
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
    public void testAuthenticateHeader() {
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
        }
    }
}
