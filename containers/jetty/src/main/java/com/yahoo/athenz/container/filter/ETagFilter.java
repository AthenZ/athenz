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

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;

@Provider
public class ETagFilter implements ContainerResponseFilter {

    @Context private jakarta.servlet.http.HttpServletResponse servletResponse;
    
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        
        // if our response object has a string ETag header value we're going
        // to replace it with its corresponding EntityTag object since the
        // the jersey GZIPResponse handler expects that object. 
        
        // We could be either setting the in the container response (this is when
        // we're returning not-modified response since we're creating the container
        // response directly) or in the servlet response (this is where we're just
        // returning our data set with the header included). 
        
        // So we'll check in the container response first and if we don't have 
        // anything there we'll check in the servlet response. If we find the 
        // header in the servlet response, we're going to remove it and set a new
        // entity tag object in the container response
        
        String etagStr = null;
        if (response.getHeaders().containsKey(HttpHeaders.ETAG)) {
            etagStr = (String) response.getHeaders().getFirst(HttpHeaders.ETAG);
        }
        if (etagStr == null && servletResponse != null) {
            etagStr = servletResponse.getHeader(HttpHeaders.ETAG);
            if (etagStr != null) {
                servletResponse.setHeader(HttpHeaders.ETAG, null);
            }
        }
        if (etagStr != null) {
            etagStr = removeLeadingAndTrailingQuotes(etagStr);
            response.getHeaders().putSingle("ETag", new EntityTag(etagStr));
        }
    }
    
    String removeLeadingAndTrailingQuotes(String value) {
        if (value.startsWith("\"")) {
            value = value.substring(1);
        }
        if (value.endsWith("\"")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
}
