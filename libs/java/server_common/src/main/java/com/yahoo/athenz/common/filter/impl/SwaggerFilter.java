/*
 *  Copyright The Athenz Authors
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

package com.yahoo.athenz.common.filter.impl;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.jetty.util.StringUtil;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static com.yahoo.athenz.common.server.rest.Http.JAVAX_CERT_ATTR;

@Provider
public class SwaggerFilter implements Filter {

    public static final String ATHENZ_SWAGGER_REQUIRE_CERT_AUTH = "athenz.swagger.require_cert_auth";

    private boolean requireCertAuth;

    public SwaggerFilter() {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {

        // if configured, we need to make sure we have a valid certificate validated by jetty

        if (requireCertAuth) {
            X509Certificate[] certs = (X509Certificate[]) servletRequest.getAttribute(JAVAX_CERT_ATTR);
            if (certs == null || certs[0] == null) {
                ((HttpServletResponse) servletResponse).sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        chain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void init(FilterConfig config) {
        final String requireCertAuthParam = config.getInitParameter(ATHENZ_SWAGGER_REQUIRE_CERT_AUTH);
        if (!StringUtil.isEmpty(requireCertAuthParam)) {
            requireCertAuth = Boolean.parseBoolean(requireCertAuthParam);
        }
    }
}
