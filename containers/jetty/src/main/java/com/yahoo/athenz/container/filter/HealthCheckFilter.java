package com.yahoo.athenz.container.filter;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.container.AthenzConsts;

public class HealthCheckFilter implements javax.servlet.Filter {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(HealthCheckFilter.class);
    
    public static final String ATHENZ_HEALTH_CHECK_STATUS_OK_BODY = "athenz.health_check_status_ok_body";
    
    private static final String HTTP_GET = "GET";
    private static final String STATUS_OK_BODY = "OK";
    
    private boolean statusOkBody = true;
    private int statusBodyLength = STATUS_OK_BODY.length();
    private String filterPath = null;
    private Map<String, File> uriList = null;

    public void init(FilterConfig config) throws ServletException {
        
        filterPath = config.getInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH);

        // if the path is not available then health check is not enabled
        
        if (filterPath == null) {
            return;
        }

        uriList = new HashMap<>();
        final String list = System.getProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST);

        if (list == null || list.isEmpty()) {
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
                    LOGGER.debug("Healthcheck filter returning " + sc);
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
