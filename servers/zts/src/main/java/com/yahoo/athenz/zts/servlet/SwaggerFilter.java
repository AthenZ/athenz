/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.servlet;

import com.yahoo.athenz.zts.ResourceContext;
import com.yahoo.athenz.zts.ZTSHandler;
import com.yahoo.athenz.zts.ZTSImplFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
public class SwaggerFilter implements Filter {

    private final ZTSHandler ztsHandler;

    public SwaggerFilter() {
        this.ztsHandler = ZTSImplFactory.getZtsInstance();
    }

    public SwaggerFilter(ZTSHandler ztsHandler) {
        this.ztsHandler = ztsHandler;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        ResourceContext context = this.ztsHandler.newResourceContext((HttpServletRequest) request,
                (HttpServletResponse) response, "swagger");
        try {
            context.authenticate();
        } catch (Exception ex) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
