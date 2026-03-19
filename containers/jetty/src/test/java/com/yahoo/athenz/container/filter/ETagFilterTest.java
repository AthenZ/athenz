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

import static org.testng.Assert.*;

import java.lang.reflect.Field;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.container.ContainerResponseContext;

import org.mockito.Mockito;

import org.testng.annotations.Test;

public class ETagFilterTest {

    ContainerResponseContext getContext(String tag) {
        ContainerResponseContext context = Mockito.mock(ContainerResponseContext.class);
        MultivaluedMap<String, Object> mvMap = new MultivaluedHashMap<>();
        mvMap.add(HttpHeaders.ETAG, tag);
        Mockito.when(context.getHeaders()).thenReturn(mvMap);
        return context;
    }

    ContainerResponseContext getEmptyContext() {
        ContainerResponseContext context = Mockito.mock(ContainerResponseContext.class);
        MultivaluedMap<String, Object> mvMap = new MultivaluedHashMap<>();
        Mockito.when(context.getHeaders()).thenReturn(mvMap);
        return context;
    }

    void setServletResponse(ETagFilter filter, HttpServletResponse servletResponse) throws Exception {
        Field field = ETagFilter.class.getDeclaredField("servletResponse");
        field.setAccessible(true);
        field.set(filter, servletResponse);
    }

    @Test
    public void testFilterContainerETagSet() {

        ContainerResponseContext containerResponse = getContext("etag");

        ETagFilter eTagFilter = new ETagFilter();
        eTagFilter.filter(null, containerResponse);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNotNull(eTag);
        assertEquals(eTag.getValue(), "etag");
    }

    @Test
    public void testFilterContainerETagSetWithQuotes() {

        ContainerResponseContext containerResponse = getContext("\"quoted-etag\"");

        ETagFilter eTagFilter = new ETagFilter();
        eTagFilter.filter(null, containerResponse);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNotNull(eTag);
        assertEquals(eTag.getValue(), "quoted-etag");
    }

    @Test
    public void testFilterContainerETagNotSet() {

        ContainerResponseContext containerResponse = getContext(null);

        ETagFilter eTagFilter = new ETagFilter();
        eTagFilter.filter(null, containerResponse);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNull(eTag);
    }

    @Test
    public void testFilterNoETagHeader() {

        ContainerResponseContext containerResponse = getEmptyContext();

        ETagFilter eTagFilter = new ETagFilter();
        eTagFilter.filter(null, containerResponse);
        assertNull(containerResponse.getHeaders().getFirst(HttpHeaders.ETAG));
    }

    @Test
    public void testFilterServletResponseETagSet() throws Exception {

        ContainerResponseContext containerResponse = getEmptyContext();

        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.when(servletResponse.getHeader(HttpHeaders.ETAG)).thenReturn("servlet-etag");

        ETagFilter eTagFilter = new ETagFilter();
        setServletResponse(eTagFilter, servletResponse);

        eTagFilter.filter(null, containerResponse);

        Mockito.verify(servletResponse).setHeader(HttpHeaders.ETAG, null);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNotNull(eTag);
        assertEquals(eTag.getValue(), "servlet-etag");
    }

    @Test
    public void testFilterServletResponseETagNotSet() throws Exception {

        ContainerResponseContext containerResponse = getEmptyContext();

        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.when(servletResponse.getHeader(HttpHeaders.ETAG)).thenReturn(null);

        ETagFilter eTagFilter = new ETagFilter();
        setServletResponse(eTagFilter, servletResponse);

        eTagFilter.filter(null, containerResponse);

        assertNull(containerResponse.getHeaders().getFirst(HttpHeaders.ETAG));
    }

    @Test
    public void testFilterContainerNullETagFallbackToServletResponse() throws Exception {

        ContainerResponseContext containerResponse = getContext(null);

        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.when(servletResponse.getHeader(HttpHeaders.ETAG)).thenReturn("fallback-etag");

        ETagFilter eTagFilter = new ETagFilter();
        setServletResponse(eTagFilter, servletResponse);

        eTagFilter.filter(null, containerResponse);

        Mockito.verify(servletResponse).setHeader(HttpHeaders.ETAG, null);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNotNull(eTag);
        assertEquals(eTag.getValue(), "fallback-etag");
    }

    @Test
    public void testFilterContainerETagSetSkipsServletResponse() throws Exception {

        ContainerResponseContext containerResponse = getContext("container-etag");

        HttpServletResponse servletResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.when(servletResponse.getHeader(HttpHeaders.ETAG)).thenReturn("servlet-etag");

        ETagFilter eTagFilter = new ETagFilter();
        setServletResponse(eTagFilter, servletResponse);

        eTagFilter.filter(null, containerResponse);

        Mockito.verify(servletResponse, Mockito.never()).getHeader(HttpHeaders.ETAG);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNotNull(eTag);
        assertEquals(eTag.getValue(), "container-etag");
    }

    @Test
    public void testRemoveLeadingAndTrailingQuotes() {

        ETagFilter eTagFilter = new ETagFilter();
        assertEquals(eTagFilter.removeLeadingAndTrailingQuotes("abc"), "abc");
        assertEquals(eTagFilter.removeLeadingAndTrailingQuotes("\"abc"), "abc");
        assertEquals(eTagFilter.removeLeadingAndTrailingQuotes("abc\""), "abc");
        assertEquals(eTagFilter.removeLeadingAndTrailingQuotes("\"abc\""), "abc");
        assertEquals(eTagFilter.removeLeadingAndTrailingQuotes("\"a\"bc\""), "a\"bc");
    }
}
