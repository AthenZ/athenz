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
import javax.servlet.http.HttpServletResponse;

import com.sun.org.apache.xpath.internal.Arg;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

import org.mockito.internal.matchers.Any;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authorizer;

public class ResourceContextTest {

    @Test
    public void testResourceContext() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        assertEquals(context.request(), httpServletRequest);
        assertEquals(context.response(), httpServletResponse);
        assertNull(context.principal());
    }

    @Test
    public void testAuthenticate() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        context.checked = true;
        assertNull(context.authenticate());
    }

    @Test
    public void testAuthenticateOptionalAuth() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);

        // with optional auth we should get null response
        assertNull(context.authenticate(true));

        // without optional auth we should get back an exception
        context.checked = false;
        try {
            context.authenticate(false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.UNAUTHORIZED);
        }
    }

    @Test
    public void testAuthorizeFailure() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse,
                authorities, authorizer);
        try {
            context.authorize("action", "resource", "domain");
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }

    @Test
    public void testAuthorize() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Principal principal = Mockito.mock(Principal.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Mockito.when(authorizer.access(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(),
                ArgumentMatchers.any(Principal.class), ArgumentMatchers.anyString())).thenReturn(true);
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authority.getHeader()).thenReturn("Athenz-Principal-Auth");
        Mockito.when(httpServletRequest.getHeader("Athenz-Principal-Auth")).thenReturn("Creds");
        Mockito.when(authority.authenticate(ArgumentMatchers.any(), ArgumentMatchers.any(),
                ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn(principal);
        Http.AuthorityList authorities = new Http.AuthorityList();
        authorities.add(authority);
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse,
                authorities, authorizer);

        context.authorize("action", "resource", "domain");
        assertTrue(true);
    }

    @Test
    public void testSendAuthenticateChallengesNot401() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        ResourceException exc = new ResourceException(403);
        context.sendAuthenticateChallenges(exc);
        Mockito.verify(httpServletRequest, times(0)).getAttribute("com.yahoo.athenz.auth.credential.challenges");
        Mockito.verify(httpServletResponse, times(0)).addHeader("WWW-Authenticate", "Negotiate");
    }

    @Test
    public void testSendAuthenticateChallengesNoChallenge() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        ResourceException exc = new ResourceException(401);
        Mockito.when(httpServletRequest.getAttribute("com.yahoo.athenz.auth.credential.challenges")).thenReturn(null);
        context.sendAuthenticateChallenges(exc);
        Mockito.verify(httpServletRequest, times(1)).getAttribute("com.yahoo.athenz.auth.credential.challenges");
        Mockito.verify(httpServletResponse, times(0)).addHeader("WWW-Authenticate", "Negotiate");
    }

    @Test
    public void testSendAuthenticateChallenges() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        ResourceException exc = new ResourceException(401);
        Mockito.when(httpServletRequest.getAttribute("com.yahoo.athenz.auth.credential.challenges")).thenReturn("Negotiate");
        context.sendAuthenticateChallenges(exc);
        Mockito.verify(httpServletRequest, times(1)).getAttribute("com.yahoo.athenz.auth.credential.challenges");
        Mockito.verify(httpServletResponse, times(1)).addHeader("WWW-Authenticate", "Negotiate");
    }
}
