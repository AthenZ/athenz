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
package com.yahoo.athenz.common.filter.impl;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

/**
 * AthenzZTSQoSFilter extends Jetty's QoSFilter to allow separate
 * handling of URIs for certificates and tokens
 * <p>
 * {@literal
 * <filter>
 *   <filter-name>AthenzZTSQoSFilterCerts</filter-name>
 *   <filter-class>com.yahoo.athenz.common.filter.impl.AthenzZTSQoSFilter</filter-class>
 *   <init-param>
 *     <param-name>certRequests</param-name>
 *     <param-value>true</param-value>
 *   </init-param>
 *   <init-param>
 *     <param-name>maxRequests</param-name>
 *     <param-value>5</param-value>
 *   </init-param>
 *   </filter>
 *   <filter-mapping>
 *     <filter-name>AthenzZTSQoSFilterCerts</filter-name>
 *     <url-pattern>/*</url-pattern>
 *   </filter-mapping>
 * </filter>
 * }
 */

public class AthenzZTSQoSFilter extends org.eclipse.jetty.ee9.servlets.QoSFilter {

    private static final Logger LOG = LoggerFactory.getLogger(AthenzZTSQoSFilter.class);

    static final String CERT_REQUESTS_INIT_PARAM = "certRequests";
    static final String HTTP_POST = "POST";

    private boolean certRequestConfig = false;
    
    @Override
    public void init(FilterConfig filterConfig) {

        final String certRequestsValue = filterConfig.getInitParameter(CERT_REQUESTS_INIT_PARAM);
        if (!StringUtil.isEmpty(certRequestsValue)) {
            certRequestConfig = Boolean.parseBoolean(certRequestsValue);
        }

        super.init(filterConfig);
    }
    
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {

        boolean certRequest = isCertRequest(servletRequest);
        if ((certRequestConfig && certRequest) || (!certRequestConfig && !certRequest)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("calling QoSFilter for processing cert-config({})/cert-request({})",
                        certRequestConfig, certRequest);
            }
            super.doFilter(servletRequest, servletResponse, chain);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("skipping to next filter in chain cert-config({})/cert-request({})",
                        certRequestConfig, certRequest);
            }
            chain.doFilter(servletRequest, servletResponse);
        }
    }

    public boolean getCertRequestConfig() {
        return certRequestConfig;
    }

    boolean isCertRequest(ServletRequest servletRequest) {

        // our host and ssh certificate request URIs are the following POST paths:
        //
        //  @Path("/instance/{provider}/{domain}/{service}/{instanceId}")
        //  @Path("/instance/{domain}/{service}/refresh")
        //  @Path("/instance")
        //  @Path("/domain/{domainName}/role/{roleName}/token") (deprecated rolecert api)
        //  @Path("/rolecert")
        //  @Path("/sshcert")

        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (LOG.isDebugEnabled()) {
            LOG.debug("processing request: {} {}", request.getMethod(), request.getRequestURI());
        }

        // so the first quick check is if the request is not a POST
        // request, then it cannot be a cert request

        if (!HTTP_POST.equalsIgnoreCase(request.getMethod())) {
            return false;
        }

        final String uri = request.getRequestURI();
        return uri.startsWith("/zts/v1/instance") ||
                uri.startsWith("/zts/v1/rolecert") ||
                uri.startsWith("/zts/v1/sshcert") ||
                (uri.startsWith("/zts/v1/domain/") && uri.endsWith("/token"));
    }
}
