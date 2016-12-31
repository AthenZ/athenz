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
package com.yahoo.athenz.common.server.filters;

import static org.testng.Assert.*;

import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.container.ContainerResponseContext;

import org.mockito.Mockito;

import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.filters.ETagFilter;

public class ETagFilterTest {

    ContainerResponseContext getContext(String tag) {
        ContainerResponseContext context = Mockito.mock(ContainerResponseContext.class);
        MultivaluedMap<String, Object> mvMap = new MultivaluedHashMap<String, Object>();
        mvMap.add(HttpHeaders.ETAG, tag);
        Mockito.when(context.getHeaders()).thenReturn(mvMap);
        return context;
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
    public void testFilterContainerETagNotSet() {

        ContainerResponseContext containerResponse = getContext(null);
        
        ETagFilter eTagFilter = new ETagFilter();
        eTagFilter.filter(null, containerResponse);
        EntityTag eTag = (EntityTag) containerResponse.getHeaders().getFirst(HttpHeaders.ETAG);
        assertNull(eTag);
    }
}
