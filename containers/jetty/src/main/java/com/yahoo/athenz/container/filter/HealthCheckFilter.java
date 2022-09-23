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

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.container.AthenzConsts;

public class HealthCheckFilter implements jakarta.servlet.Filter {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(HealthCheckFilter.class);
    
    public static final String ATHENZ_HEALTH_CHECK_STATUS_OK_BODY = "athenz.health_check_status_ok_body";
    
    private static final String HTTP_GET = "GET";
    private static final String STATUS_OK_BODY = "OK";
    
    private boolean statusOkBody = true;
    private final int statusBodyLength = STATUS_OK_BODY.length();
    private Map<String, File> uriList = null;

    public void init(FilterConfig config) {

        final String filterPath = config.getInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH);

        // if the path is not available then health check is not enabled
        
        if (filterPath == null) {
            return;
        }

        uriList = new HashMap<>();
        final String list = System.getProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST);
        if (StringUtil.isEmpty(list)) {
            return;
        }
        
        String[] uris = list.split(",");
        for (String uri : uris) {
            final String trimmedUri = uri.trim();
            final String filename = (trimmedUri.indexOf(0) == '/') ? trimmedUri.substring(1) : trimmedUri;
            File uriFile = new File(filterPath, filename);
            uriList.put(trimmedUri, uriFile);
        }
        
        statusOkBody = Boolean.parseBoolean(System.getProperty(ATHENZ_HEALTH_CHECK_STATUS_OK_BODY, "true"));
    }

    public void doFilter(ServletRequest servletRequest,
            ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {

        // before doing anything make sure we have this configured
        // and we're dealing with a GET request
        
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        if (uriList != null && !uriList.isEmpty() && HTTP_GET.equals(request.getMethod())) {
            
            final File file = uriList.get(request.getRequestURI());
            if (file != null) {
                int sc = getHealthCheckStatus(file);
                String msg = null;
                if (statusOkBody && sc == HttpServletResponse.SC_OK) {
                    msg = STATUS_OK_BODY;
                }
                
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Healthcheck filter returning {} for file {}", sc, file.getAbsolutePath());
                }

                response.setStatus(sc);
                if (msg != null) {
                    PrintWriter printWriter = response.getWriter();
                    if (printWriter != null) {
                        printWriter.write(msg);
                        response.setContentLength(statusBodyLength);
                    }
                } else {
                    response.setContentLength(0);
                }
                return;
            }
        }
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Healthcheck filter fell through");
        }

        // fall through to filtering
        
        chain.doFilter(servletRequest, servletResponse);
    }

    public void destroy() {
    }

    private int getHealthCheckStatus(final File file) {
        if (file.exists()) {
            return HttpServletResponse.SC_OK;
        } else {
            return HttpServletResponse.SC_NOT_FOUND;
        }
    }
}
