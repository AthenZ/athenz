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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import jakarta.servlet.ServletContext;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.yahoo.athenz.common.messaging.DomainChangeMessage.ObjectType.DOMAIN;
import static com.yahoo.athenz.common.messaging.DomainChangeMessage.ObjectType.ROLE;
import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class RsrcCtxWrapperTest {

    @Test
    public void testRsrcCtxWrapperSimpleAssertion() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

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
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName", false);

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
        ServletContext servletContext = Mockito.mock(ServletContext.class);

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
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName", false);

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
        ServletContext servletContext = Mockito.mock(ServletContext.class);

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
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName", false);

        wrapper.authorize("add-domain", "test", "test");

        // after authorize success, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test(expectedExceptions = { ResourceException.class })
    public void testAuthorizeInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName", false);

        // when not set authority
        wrapper.authorize("add-domain", "test", "test");
    }

    @Test
    public void testLogPrincipalNull() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName", false);

        wrapper.logPrincipal();
        assertNull(servletRequest.getAttribute("com.yahoo.athenz.auth.principal"));
    }

    @Test
    public void testLogPrincipal() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        X509Certificate x509Certificate = Mockito.mock(X509Certificate.class);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(BigInteger.TEN);
        principal.setX509Certificate(x509Certificate);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(principal);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);
        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, timerMetric, "apiName", false);

        wrapper.authenticate();
        wrapper.logPrincipal();

        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.principal", "hockey.kings");
        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.authority_id", "Auth-NTOKEN");
        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.principal_x509_serial", "10");
    }

    @Test
    public void testThrowZtsException() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName", false);

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
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName", false);

        wrapper.logAuthorityId(null);
        assertNull(servletRequest.getAttribute("com.yahoo.athenz.auth.authority_id"));

        wrapper.logAuthorityId(new PrincipalAuthority());
        assertEquals(servletRequest.getAttribute("com.yahoo.athenz.auth.authority_id"), "Auth-NTOKEN");
    }

    @Test
    public void testDomainChangeMessage() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
            authListMock, false, authorizerMock, timerMetric, "apiName", true);

        assertNull(wrapper.getDomainChangeMessages());

        // add domain msg
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
            .setDomainName("domain1Name")
            .setObjectName("domain1Name1")
            .setObjectType(DOMAIN));

        // add domain msg for the same domain - should be ignored
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
            .setDomainName("domain1Name")
            .setObjectName("domain1Name2")
            .setObjectType(DOMAIN));

        // add role msg for the same domain
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
            .setDomainName("domain1Name")
            .setObjectName("domain1role")
            .setObjectType(ROLE));
        
        // add domain msg for other domain
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
            .setDomainName("domain2Name")
            .setObjectName("domain2Name1")
            .setObjectType(DOMAIN));

        List<DomainChangeMessage> messages = wrapper.getDomainChangeMessages();
        
        assertEquals(messages.size(), 3);

        assertEquals(messages.get(0).getDomainName(), "domain1Name");
        assertEquals(messages.get(1).getDomainName(), "domain1Name");
        assertEquals(messages.get(2).getDomainName(), "domain2Name");

        assertEquals(messages.get(0).getObjectType(), DOMAIN);
        assertEquals(messages.get(1).getObjectType(), ROLE);
        assertEquals(messages.get(2).getObjectType(), DOMAIN);

        assertEquals(messages.get(0).getObjectName(), "domain1Name1");
        assertEquals(messages.get(1).getObjectName(), "domain1role");
        assertEquals(messages.get(2).getObjectName(), "domain2Name1");
    }

    @Test
    public void testDomainChangeMessageDisabled() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Object timerMetric = new Object();
        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, timerMetric, "apiName", false);

        assertNull(wrapper.getDomainChangeMessages());

        // add domain msg
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
                .setDomainName("domain1Name")
                .setObjectName("domain1Name1")
                .setObjectType(DOMAIN));

        // add role msg for the same domain
        wrapper.addDomainChangeMessage(new DomainChangeMessage()
                .setDomainName("domain1Name")
                .setObjectName("domain1role")
                .setObjectType(ROLE));

        assertNull(wrapper.getDomainChangeMessages());
    }
}
