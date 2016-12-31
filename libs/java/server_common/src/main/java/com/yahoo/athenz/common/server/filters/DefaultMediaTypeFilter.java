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

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;

import static javax.ws.rs.core.HttpHeaders.ACCEPT;

/*
 * If requestor specified any type Accepted, this will reset it to a
 * predictable default of application/json
 */

@PreMatching
public class DefaultMediaTypeFilter implements ContainerRequestFilter {

    final static String MEDIA_TYPE_ANY  = "*/*";
    final static String MEDIA_TYPE_JSON = "application/json";
    
    @Override
    public void filter(ContainerRequestContext reqCtx) {

        String acceptHdr = reqCtx.getHeaderString(ACCEPT);
        if (acceptHdr == null || acceptHdr.contains(MEDIA_TYPE_ANY)) {
            // replace it with JSON
            javax.ws.rs.core.MultivaluedMap<String, String> headers = reqCtx.getHeaders();
            headers.putSingle(ACCEPT, MEDIA_TYPE_JSON);
        }
    }
}
