//package com.yahoo.athenz.container.filter;
//
//import static org.testng.Assert.*;
//
//import org.testng.annotations.BeforeClass;
//import org.testng.annotations.Test;
//
//import java.io.IOException;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//
//import javax.servlet.FilterChain;
//import javax.servlet.FilterConfig;
//import javax.servlet.ServletException;
//import javax.servlet.ServletRequest;
//import javax.servlet.ServletResponse;
//
//import static org.mockito.Mockito.*;
//
//public class HealthCheckFilterTest {
//
//    FilterConfig filterConfig = null;
//    
//    @BeforeClass
//    public void setupFilterConfig () {
//        
//        filterConfig = mock(FilterConfig.class);
//        when(filterConfig.getInitParameter(HealthCheckFilter.ATHENZ_HEALTHCHECK_PATH))
//            .thenReturn("/tmp/var/athenz_test");
//    }
//    
//    private class HealthcheckFilterChain implements FilterChain {
//
//        @Override
//        public void doFilter(ServletRequest arg0, ServletResponse arg1)
//                throws IOException, ServletException {
//        }
//    }
//    
//    @Test
//    public void testVIPCheckEnabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.vip_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status.html");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status.html");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 200);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status.html");
//    }
//    
//    @Test
//    public void testVIPCheckEnabledNoFile() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.vip_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        deleteFile("/tmp/var/athenz_test/status.html");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status.html");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 404);
//        
//        filter.destroy();
//    }
//    
//    @Test
//    public void testVIPCheckDisabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.vip_status_check", "false");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status.html");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status.html");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 0);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status.html");
//    }
//    
//    @Test
//    public void testBrooklynCheckEnabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.brooklyn_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/akamai");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/akamai");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 200);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/akamai");
//    }
//    
//    @Test
//    public void testBrooklynCheckEnabledNoFile() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.brooklyn_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        deleteFile("/tmp/var/athenz_test/akamai");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/akamai");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 404);
//        
//        filter.destroy();
//    }
//    
//    @Test
//    public void testBrooklynCheckDisabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.brooklyn_status_check", "false");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/akamai");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/akamai");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 0);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/akamai");
//    }
//    
//    @Test
//    public void testCheckWrongMethod() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.vip_status_check", "true");
//        System.setProperty("yahoo.athenz.brooklyn_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status.html");
//        createFile("/tmp/var/athenz_test/akamai");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("PUT");
//        request.setRequestURI("/status.html");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 0);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status.html");
//        deleteFile("/tmp/var/athenz_test/akamai");
//    }
//    
//    @Test
//    public void testCheckWrongURI() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.vip_status_check", "true");
//        System.setProperty("yahoo.athenz.brooklyn_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status.html");
//        createFile("/tmp/var/athenz_test/akamai");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 0);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status.html");
//        deleteFile("/tmp/var/athenz_test/akamai");
//    }
//    
//    @Test
//    public void testCloudCheckEnabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.cloud_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 200);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status");
//    }
//    
//    @Test
//    public void testCloudCheckEnabledNoFile() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.cloud_status_check", "true");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        deleteFile("/tmp/var/athenz_test/status");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 404);
//        
//        filter.destroy();
//    }
//    
//    @Test
//    public void testCloudCheckDisabled() {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.cloud_status_check", "false");
//        
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 0);
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status");
//    }
//    
//    @Test
//    public void testCloudCheckEnabledMsgBody() throws IOException {
//        
//        HealthCheckFilter filter = new HealthCheckFilter();
//        assertNotNull(filter);
//        
//        System.setProperty("yahoo.athenz.cloud_status_check", "true");
//        System.setProperty("yahoo.athenz.cloud_status_ok_body", "true");
//
//        try {
//            filter.init(filterConfig);
//        } catch (ServletException e1) {
//            fail();
//        }
//        
//        createFile("/tmp/var/athenz_test/status");
//        
//        MockHttpServletRequest request =  new MockHttpServletRequest();
//        request.setMethod("GET");
//        request.setRequestURI("/status");
//        
//        MockHttpServletResponse response =  new MockHttpServletResponse();
//        
//        HealthcheckFilterChain chain = new HealthcheckFilterChain();
//        
//        try {
//            filter.doFilter(request, response, chain);
//        } catch (IOException e) {
//            fail();
//        } catch (ServletException e) {
//            fail();
//        }
//        assertEquals(response.getStatus(), 200);
//        assertEquals(response.getContentLength(), 2);
//        assertEquals(response.getWriterData(), "OK");
//        
//        filter.destroy();
//        deleteFile("/tmp/var/athenz_test/status");
//        System.clearProperty("yahoo.athenz.cloud_status_ok_body");
//    }
//    
//    private void createFile(String filename) {
//        try {
//            Path pathToFile = Paths.get(filename);
//            Files.createDirectories(pathToFile.getParent());
//            Files.createFile(pathToFile);
//        } catch (IOException e) {
//        }
//    }
//
//    private void deleteFile(String filename) {
//        try {
//            Path pathToFile = Paths.get(filename);
//            Files.delete(pathToFile);
//        } catch (IOException e) {
//        }
//    }
//}