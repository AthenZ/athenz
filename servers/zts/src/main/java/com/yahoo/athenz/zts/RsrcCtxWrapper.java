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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.KerberosAuthority;
import com.yahoo.athenz.common.server.rest.Http;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RsrcCtxWrapper implements ResourceContext {
    
    static final String HEADER_NAME_KRB_AUTH = "Authorization";
    static final String HEADER_NAME_WWW_AUTHENTICATE = "WWW-Authenticate";
    static final String HEADER_VALUE_NEGOTIATE = "negotiate";

    com.yahoo.athenz.common.server.rest.ResourceContext ctx = null;

    public RsrcCtxWrapper(HttpServletRequest request, HttpServletResponse response, Http.AuthorityList authList, Authorizer authorizer) {
        ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(request, response, authList, authorizer);
    }

    public com.yahoo.athenz.common.server.rest.ResourceContext context() {
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
            ctx.authenticate();
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            throwZtsException(restExc);
        }
    }

    public void authenticateKerberos() {
        try {
            ctx.authenticate();
            
            // we must verify that the authority is the kerberos
            // authority responsible for authentication

            if (!(ctx.principal().getAuthority() instanceof KerberosAuthority)) {
                throw new com.yahoo.athenz.common.server.rest.ResourceException(com.yahoo.athenz.common.server.rest.ResourceException.UNAUTHORIZED);
            }
            
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            
            // if the request does not contain kerberos authorization header,
            // we're going to add the expected header to the response
            
            if (ctx.request().getHeader(HEADER_NAME_KRB_AUTH) == null) {
                ctx.response().addHeader(HEADER_NAME_WWW_AUTHENTICATE, HEADER_VALUE_NEGOTIATE);
            }
            
            throwZtsException(restExc);
        }
    }
    
    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            throwZtsException(restExc);
        }
    }

    public void throwZtsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {
        String msg = null;
        Object data = restExc.getData();
        if (data instanceof String) {
            msg = (String) data;
        }
        if (msg == null) {
            msg = restExc.getMessage();
        }
        throw new com.yahoo.athenz.zts.ResourceException(restExc.getCode(),
                new ResourceError().code(restExc.getCode()).message(msg));
    }
    
}
