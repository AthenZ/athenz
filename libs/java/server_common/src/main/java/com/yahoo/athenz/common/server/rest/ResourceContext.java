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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;

public class ResourceContext  {
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final Http.AuthorityList authorities;
    private final Authorizer authorizer;

    protected Principal principal;
    protected boolean checked;

    public ResourceContext(HttpServletRequest request, HttpServletResponse response,
            Http.AuthorityList authorities, Authorizer authorizer) {
        this.request = request;
        this.response = response;
        this.authorities = authorities;
        this.authorizer = authorizer;
        this.principal = null;
        this.checked = false;
    }

    public HttpServletRequest request() {
        return request;
    }

    public HttpServletResponse response() {
        return response;
    }

    public Principal principal() {
        return principal;
    }

    //throws an exception if it cannot authenticate
    public Principal authenticate() {
        if (!checked) {
            checked = true;
            principal = Http.authenticate(request, authorities);
        }
        return principal;
    }

    //throws an exception if it cannot authorize
    public void authorize(String action, String resource, String trustedDomain) {
        principal = authenticate();
        Http.authorize(authorizer, principal, action, resource, trustedDomain);
    }
}
