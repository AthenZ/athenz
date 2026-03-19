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
package com.yahoo.athenz.container.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.testng.annotations.Test;

import static jakarta.ws.rs.core.HttpHeaders.ACCEPT;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class DefaultMediaTypeFilterTest {

    @Test
    public void testFilterNullAcceptHeader() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn(null);
        when(reqCtx.getHeaders()).thenReturn(headers);

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        assertEquals(headers.getFirst(ACCEPT), "application/json");
    }

    @Test
    public void testFilterAnyMediaType() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn("*/*");
        when(reqCtx.getHeaders()).thenReturn(headers);

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        assertEquals(headers.getFirst(ACCEPT), "application/json");
    }

    @Test
    public void testFilterAnyMediaTypeAmongOthers() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn("text/html, */*;q=0.8");
        when(reqCtx.getHeaders()).thenReturn(headers);

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        assertEquals(headers.getFirst(ACCEPT), "application/json");
    }

    @Test
    public void testFilterSpecificMediaTypeNotReplaced() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn("text/html");

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        verify(reqCtx, never()).getHeaders();
    }

    @Test
    public void testFilterJsonMediaTypeNotReplaced() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn("application/json");

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        verify(reqCtx, never()).getHeaders();
    }

    @Test
    public void testFilterXmlMediaTypeNotReplaced() {
        ContainerRequestContext reqCtx = mock(ContainerRequestContext.class);

        when(reqCtx.getHeaderString(ACCEPT)).thenReturn("application/xml");

        DefaultMediaTypeFilter filter = new DefaultMediaTypeFilter();
        filter.filter(reqCtx);

        verify(reqCtx, never()).getHeaders();
    }

    @Test
    public void testPreMatchingAnnotation() {
        assertTrue(DefaultMediaTypeFilter.class.isAnnotationPresent(PreMatching.class));
    }

    @Test
    public void testConstants() {
        assertEquals(DefaultMediaTypeFilter.MEDIA_TYPE_ANY, "*/*");
        assertEquals(DefaultMediaTypeFilter.MEDIA_TYPE_JSON, "application/json");
    }
}
