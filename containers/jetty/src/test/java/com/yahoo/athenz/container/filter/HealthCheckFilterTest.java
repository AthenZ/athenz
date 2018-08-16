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
package com.yahoo.athenz.container.filter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.container.AthenzConsts;

public class HealthCheckFilterTest {

    FilterConfig filterConfig = null;
    
    @BeforeClass
    public void setupFilterConfig () {
        
        filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_PATH))
            .thenReturn("/tmp/var/athenz_test");
    }
    
    private class HealthcheckFilterChain implements FilterChain {

        @Override
        public void doFilter(ServletRequest arg0, ServletResponse arg1) {
        }
    }
    
    @Test
    public void testCheckEnabledSingleUri() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html");
        
        try {
            filter.init(filterConfig);
        } catch (ServletException e1) {
            fail();
        }
        
        createFile("/tmp/var/athenz_test/status.html");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status.html");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        
        filter.destroy();
        deleteFile("/tmp/var/athenz_test/status.html");
    }
    
    @Test
    public void testCheckEnabledMultipleUri() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html,/status");
        
        try {
            filter.init(filterConfig);
        } catch (ServletException e1) {
            fail();
        }
        
        createFile("/tmp/var/athenz_test/status");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 200);
        
        filter.destroy();
        deleteFile("/tmp/var/athenz_test/status");
    }
    
    @Test
    public void testCheckEnabledNoFile() {
        
        HealthCheckFilter filter = new HealthCheckFilter();
        assertNotNull(filter);
        
        System.setProperty(AthenzConsts.ATHENZ_PROP_HEALTH_CHECK_URI_LIST, "/status.html");
        
        try {
            filter.init(filterConfig);
        } catch (ServletException e1) {
            fail();
        }
        
        deleteFile("/tmp/var/athenz_test/status.html");
        
        MockHttpServletRequest request =  new MockHttpServletRequest();
        request.setMethod("GET");
        request.setRequestURI("/status.html");
        
        MockHttpServletResponse response =  new MockHttpServletResponse();
        
        HealthcheckFilterChain chain = new HealthcheckFilterChain();
        
        try {
            filter.doFilter(request, response, chain);
        } catch (IOException | ServletException e) {
            fail();
        }
        assertEquals(response.getStatus(), 404);
        
        filter.destroy();
    }
    
    private void createFile(String filename) {
        try {
            Path pathToFile = Paths.get(filename);
            Files.createDirectories(pathToFile.getParent());
            Files.createFile(pathToFile);
        } catch (IOException ignored) {
        }
    }

    private void deleteFile(String filename) {
        try {
            Path pathToFile = Paths.get(filename);
            Files.delete(pathToFile);
        } catch (IOException ignored) {
        }
    }
}