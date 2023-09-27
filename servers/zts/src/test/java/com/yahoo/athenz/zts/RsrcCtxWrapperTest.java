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
package com.yahoo.athenz.zts;

import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import com.yahoo.athenz.common.metrics.Metric;

import com.yahoo.athenz.common.server.rest.Http.AuthorityList;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

public class RsrcCtxWrapperTest {

    @Test
    public void testRsrcCtxWrapperSimpleAssertion() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);
        
        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        assertNotNull(wrapper.context());

        // default principal should be null
        assertNull(wrapper.principal());

        assertEquals(wrapper.request(), reqMock);
        assertEquals(wrapper.response(), resMock);
        assertEquals(wrapper.getApiName(), "apiname");
        assertEquals(wrapper.getHttpMethod(), "POST");

        wrapper.authenticate();

        // after authenticate, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test
    public void testRsrcCtxWrapperSimpleAssertionMtlsRestricted() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getMtlsRestricted()).thenReturn(true);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        assertNotNull(wrapper.context());

        // default principal should be null
        assertNull(wrapper.principal());

        assertEquals(wrapper.request(), reqMock);
        assertEquals(wrapper.response(), resMock);
        assertEquals(wrapper.getApiName(), "apiname");
        assertEquals(wrapper.getHttpMethod(), "POST");

        try {
            wrapper.authenticate();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"certificate is mTLS restricted\"}");
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testAuthenticateException() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenThrow(new com.yahoo.athenz.common.server.rest.ResourceException(403));
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

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
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);
        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        wrapper.authorize("add-domain", "test", "test");

        // after authorize success, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test
    public void testAuthorizeMtlsRestricted() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);
        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getMtlsRestricted()).thenReturn(true);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        try {
            wrapper.authorize("add-domain", "test", "test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (403): {code: 403, message: \"mTLS Restricted\"}");
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test(expectedExceptions = { ResourceException.class })
    public void testAuthorizeInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

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
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName");

        wrapper.logPrincipal();
        assertNull(servletRequest.getAttribute("com.yahoo.athenz.auth.principal"));

        wrapper.logPrincipal(null);
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
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        X509Certificate x509Certificate = Mockito.mock(X509Certificate.class);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(BigInteger.TEN);
        principal.setX509Certificate(x509Certificate);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(principal);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        wrapper.authenticate();
        wrapper.logPrincipal();

        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.principal", "hockey.kings");
        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.authority_id", "Auth-NTOKEN");
        Mockito.verify(reqMock, times(1)).setAttribute("com.yahoo.athenz.auth.principal_x509_serial", "10");
    }

    @Test
    public void testLogPrincipalRoleName() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setRolePrincipalName("athenz.role");

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(principal);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName");

        wrapper.authenticate();
        assertEquals("athenz.role", wrapper.logPrincipal());
        assertEquals("hockey", wrapper.getPrincipalDomain());
    }

    @Test
    public void testThrowZtsException() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
                authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName");

        com.yahoo.athenz.common.server.rest.ResourceException restExc =
                new com.yahoo.athenz.common.server.rest.ResourceException(503, null);

        try {
            wrapper.throwZtsException(restExc);
            fail();
        } catch (ResourceException ex) {
            assertEquals(503, ex.getCode());
        }
    }

    @Test
    public void testDomainChanges() {

        HttpServletRequest servletRequest = new MockHttpServletRequest();
        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, servletRequest, servletResponse,
            authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName");
        
        wrapper.addDomainChangeMessage(new DomainChangeMessage());
        
        assertNull(wrapper.getDomainChangeMessages());
    }
}
