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

import com.yahoo.athenz.common.server.ServerResourceException;
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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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

        // update the principal and verify the new value
        Principal newPrincipal = Mockito.mock(Principal.class);
        wrapper.setPrincipal(newPrincipal);
        assertEquals(wrapper.principal(), newPrincipal);
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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                .thenThrow(new ResourceException(403));
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

        try {
            wrapper.authenticate();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

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
                authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

        wrapper.authenticate();
        assertEquals(wrapper.logPrincipal(), "athenz.role");
        assertEquals(wrapper.getPrincipalDomain(), "hockey");
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
                authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

        ServerResourceException restExc =
                new ServerResourceException(503, null);

        try {
            wrapper.throwZtsException(restExc);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 503);
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
            authListMock, false, authorizerMock, metricMock, timerMetricMock, "apiName", null, null);

        wrapper.addDomainChangeMessage(new DomainChangeMessage());

        assertNull(wrapper.getDomainChangeMessages());
    }

    @Test
    public void testAuthenticateUserPrincipalValid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Authority userAuthority = Mockito.mock(Authority.class);
        Mockito.when(userAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        wrapper.authenticate();
        assertEquals(wrapper.principal(), prin);
    }

    @Test
    public void testAuthenticateUserPrincipalInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Authority userAuthority = Mockito.mock(Authority.class);
        Mockito.when(userAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_INVALID);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        try {
            wrapper.authenticate();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user is not valid\"}");
        }
    }

    @Test
    public void testAuthenticateUserPrincipalSuspended() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Authority userAuthority = Mockito.mock(Authority.class);
        Mockito.when(userAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_SUSPENDED);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        try {
            wrapper.authenticate();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testAuthenticateNonUserDomainSkipsValidation() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("sports");
        Mockito.when(prin.getFullName()).thenReturn("sports.api");

        Authority userAuthority = Mockito.mock(Authority.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        wrapper.authenticate();
        assertEquals(wrapper.principal(), prin);
        Mockito.verify(userAuthority, Mockito.never()).getUserType(Mockito.anyString());
    }

    @Test
    public void testAuthorizeUserPrincipalValid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Authority userAuthority = Mockito.mock(Authority.class);
        Mockito.when(userAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        wrapper.authorize("add-domain", "test", "test");
        assertEquals(wrapper.principal(), prin);
    }

    @Test
    public void testAuthorizeUserPrincipalInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Authority userAuthority = Mockito.mock(Authority.class);
        Mockito.when(userAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_INVALID);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        Mockito.when(authorizerMock.access(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", userAuthority, "user");

        try {
            wrapper.authorize("add-domain", "test", "test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertEquals(ex.getMessage(), "ResourceException (401): {code: 401, message: \"user is not valid\"}");
        }
    }

    @Test
    public void testAuthenticateNullUserAuthoritySkipsValidation() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);
        ServletContext servletContext = Mockito.mock(ServletContext.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);
        Metric metricMock = Mockito.mock(Metric.class);
        Object timerMetricMock = Mockito.mock(Object.class);

        Principal prin = Mockito.mock(Principal.class);
        Mockito.when(prin.getDomain()).thenReturn("user");
        Mockito.when(prin.getFullName()).thenReturn("user.joe");

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(servletContext, reqMock, resMock, authListMock, false,
                authorizerMock, metricMock, timerMetricMock, "apiName", null, "user");

        wrapper.authenticate();
        assertEquals(wrapper.principal(), prin);
    }
}
