/*
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.zms;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.rest.Http;

public class RsrcCtxWrapper implements ResourceContext {

    private static final String ZMS_REQUEST_PRINCIPAL   = "com.yahoo.athenz.auth.principal";

    private final com.yahoo.athenz.common.server.rest.ResourceContext ctx;
    private boolean optionalAuth;
    
    RsrcCtxWrapper(HttpServletRequest request, HttpServletResponse response,
                   Http.AuthorityList authList, boolean optionalAuth,
                   Authorizer authorizer) {
        this.optionalAuth = optionalAuth;
        ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(request,
                response, authList, authorizer);
    }

    com.yahoo.athenz.common.server.rest.ResourceContext context() {
        return ctx;
    }

    public Principal principal() {
        return ctx.principal();
    }

    @Override
    public HttpServletRequest request() {
        return ctx.request();
    }

    @Override
    public HttpServletResponse response() {
        return ctx.response();
    }

    @Override
    public void authenticate() {
        try {
            ctx.authenticate(optionalAuth);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            throwZmsException(restExc);
        }
    }

    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            logPrincipal(ctx.principal());
            throwZmsException(restExc);
        }
    }

    public void logPrincipal(final Principal principal) {
        if (principal == null) {
            return;
        }
        ctx.request().setAttribute(ZMS_REQUEST_PRINCIPAL, principal.getFullName());
    }
    
    void throwZmsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {

        // first check to see if this is an auth failure and if
        // that's the case include the WWW-Authenticate challenge

        ctx.sendAuthenticateChallenges(restExc);

        // now throw a ZMS exception based on the rest exception

        String msg  = null;
        Object data = restExc.getData();
        if (data instanceof String) {
            msg = (String) data;
        }
        if (msg == null) {
            msg = restExc.getMessage();
        }
        throw new com.yahoo.athenz.zms.ResourceException(restExc.getCode(),
                new ResourceError().code(restExc.getCode()).message(msg));
    }
}
