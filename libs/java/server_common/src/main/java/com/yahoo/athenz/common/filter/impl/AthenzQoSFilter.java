/*
 * Copyright 2018 Oath, Inc.
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

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * AthenzQoSFilter is disabled by default unlike QoSFilter.
 * FilterConfig is replaced by System properties to allow configuration through properties files.
 * 
 * <filter>
        <filter-name>AthenzQoSFilter</filter-name>
        <filter-class>com.yahoo.athenz.common.filter.impl.AthenzQoSFilter</filter-class>
        <init-param>
            <param-name>athenz.qos.war</param-name>
            <param-value>zts</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>AthenzQoSFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    
 * @author charlesk
 *
 */
public class AthenzQoSFilter extends org.eclipse.jetty.servlets.QoSFilter {

    static final String ATHENZ_PROP_QOS_PREFIX = "athenz.qos.";
    static final String ATHENZ_PROP_QOS_WAR = ATHENZ_PROP_QOS_PREFIX + "war";
    
    private boolean enabled = false;
    
    @Override
    public void init(FilterConfig filterConfig) {
        String war = filterConfig.getInitParameter(ATHENZ_PROP_QOS_WAR);
        String enabledProperty = ATHENZ_PROP_QOS_PREFIX + war + ".enabled";
        if (null != System.getProperty(enabledProperty)) {
            this.enabled = Boolean.parseBoolean(System.getProperty(enabledProperty));
        }

        super.init(new PropertyFilterConfig(war));
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (this.enabled) {
            super.doFilter(request, response, chain);
        }
    }
    
    class PropertyFilterConfig implements FilterConfig {
        private final String war;
        
        PropertyFilterConfig(String war) {
            this.war = war;
        }
        
        @Override
        public String getFilterName() {
            return null;
        }

        @Override
        public ServletContext getServletContext() {
            return null;
        }

        @Override
        public String getInitParameter(String name) {
            // example: athenz.qos.zts.maxRequests
            if (null == this.war) {
                return System.getProperty(ATHENZ_PROP_QOS_PREFIX + name);
            } 
            return System.getProperty(ATHENZ_PROP_QOS_PREFIX + this.war + "." + name);
        }

        @Override
        public Enumeration<String> getInitParameterNames() {
            return null;
        }
        
    }
}
