/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.testng.Assert.*;

public class RsrcCtxWrapperTest {

    @Test
    public void testRsrcCtxWrapperSimpleAssertion() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);
        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName");

        assertNotNull(wrapper.context());

        // default principal should be null
        assertNull(wrapper.principal());

        assertEquals(wrapper.request(), reqMock);
        assertEquals(wrapper.response(), resMock);
        assertEquals(wrapper.getApiName(), "apiname");
        assertEquals(wrapper.getHttpMethod(), "POST");
        assertEquals(wrapper.getTimerMetric(), timerMetric);

        wrapper.authenticate();

        // after authenticate, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test
    public void testAuthenticateException() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new com.yahoo.athenz.common.server.rest.ResourceException(403));
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName");

        try {
            wrapper.authenticate();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
    }

    @Test
    public void testAuthorize() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, false, authorizerMock, timerMetric, "apiName");

        wrapper.authorize("add-domain", "test", "test");

        // after authorize success, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test(expectedExceptions = { ResourceException.class })
    public void testAuthorizeInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, false, authorizerMock, timerMetric, "apiName");

        // when not set authority
        wrapper.authorize("add-domain", "test", "test");
    }

    @Test
    public void testLogPrincipal() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName");

        wrapper.logPrincipal(null);
        assertNull(servletRequest.getAttribute("com.yahoo.athenz.auth.principal"));

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());

        wrapper.logPrincipal(principal);
        assertEquals(servletRequest.getAttribute("com.yahoo.athenz.auth.principal"), "hockey.kings");
        assertEquals(servletRequest.getAttribute("com.yahoo.athenz.auth.authority_id"), "Auth-NTOKEN");
    }

    @Test
    public void testThrowZtsException() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName");

        com.yahoo.athenz.common.server.rest.ResourceException restExc =
                new com.yahoo.athenz.common.server.rest.ResourceException(503, null);

        try {
            wrapper.throwZmsException(restExc);
            fail();
        } catch (ResourceException ex) {
            assertEquals(503, ex.getCode());
        }
    }

    @Test
    public void testLogAuthorityId() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName");

        wrapper.logAuthorityId(null);
        assertNull(servletRequest.getAttribute("com.yahoo.athenz.auth.authority_id"));

        wrapper.logAuthorityId(new PrincipalAuthority());
        assertEquals(servletRequest.getAttribute("com.yahoo.athenz.auth.authority_id"), "Auth-NTOKEN");
    }
}
