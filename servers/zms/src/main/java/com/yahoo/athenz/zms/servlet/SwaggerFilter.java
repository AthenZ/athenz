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

package com.yahoo.athenz.zms.servlet;

import com.yahoo.athenz.zms.ResourceContext;
import com.yahoo.athenz.zms.ZMSHandler;
import com.yahoo.athenz.zms.ZMSImplFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
public class SwaggerFilter implements javax.servlet.Filter {

    private final ZMSHandler zmsHandler = ZMSImplFactory.getZmsInstance();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        ResourceContext context = this.zmsHandler.newResourceContext((HttpServletRequest) request, (HttpServletResponse) response, "swagger");
        context.authenticate();
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
