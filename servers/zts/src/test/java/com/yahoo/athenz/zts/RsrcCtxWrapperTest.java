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
package com.yahoo.athenz.zts;

import static org.testng.Assert.*;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.rest.Http.AuthorityList;

public class RsrcCtxWrapperTest {

    @Test
    public void TestRsrcCtxWrapperSimpleAssertion() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);

        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, authorizerMock);

        assertNotNull(wrapper.context());

        // default principal should be null
        assertEquals(wrapper.principal(), null);

        assertEquals(wrapper.request(), reqMock);
        assertEquals(wrapper.response(), resMock);

        wrapper.authenticate();

        // after authenticate, principal should be set
        assertEquals(wrapper.principal(), prin);

        // invalid kerberos request
        try {
            wrapper.authenticateKerberos();
            fail();
        } catch (ResourceException ex) {
            assertNotNull(ex);
        }
    }

    @Test
    public void TestAuthorize() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);
        Authority authMock = Mockito.mock(Authority.class);

        Principal prin = Mockito.mock(Principal.class);

        Mockito.when(authMock.getHeader()).thenReturn("testheader");
        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(authMock.getCredSource()).thenReturn(com.yahoo.athenz.auth.Authority.CredSource.HEADER);
        Mockito.when(authMock.authenticate(Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.any()))
                .thenReturn(prin);
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");
        authListMock.add(authMock);

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, authorizerMock);

        wrapper.authorize("add-domain", "test", "test");

        // after authorize success, principal should be set
        assertEquals(wrapper.principal(), prin);
    }

    @Test(expectedExceptions = { ResourceException.class })
    public void TestAuthorizeInvalid() {
        HttpServletRequest reqMock = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse resMock = Mockito.mock(HttpServletResponse.class);

        AuthorityList authListMock = new AuthorityList();
        Authorizer authorizerMock = Mockito.mock(Authorizer.class);

        Mockito.when(reqMock.getHeader("testheader")).thenReturn("testcred");
        Mockito.when(reqMock.getRemoteAddr()).thenReturn("1.1.1.1");
        Mockito.when(reqMock.getMethod()).thenReturn("POST");

        // force true access right
        Mockito.when(authorizerMock.access(Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any()))
                .thenReturn(true);

        RsrcCtxWrapper wrapper = new RsrcCtxWrapper(reqMock, resMock, authListMock, authorizerMock);

        // when not set authority
        wrapper.authorize("add-domain", "test", "test");
    }
}
