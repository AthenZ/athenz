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
import javax.servlet.http.HttpServletResponse;

import org.mockito.Mockito;

import static org.testng.Assert.*;
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
    public void testAuthorize() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Http.AuthorityList authorities = new Http.AuthorityList();
        ResourceContext context = new ResourceContext(httpServletRequest, httpServletResponse, authorities, authorizer);
        try {
            context.authorize("action", "resource", "domain");
        } catch (ResourceException expected) {
            assertEquals(expected.getCode(), 401);
        }
    }
}
