package com.yahoo.athenz.container.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;

public class DisableTraceFilterTest {

    private DisableTraceFilter filter;
    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;
    private FilterChain mockChain;

    @BeforeMethod
    public void setUp() throws Exception {
        filter = new DisableTraceFilter();
        filter.init(mock(FilterConfig.class));

        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockChain = mock(FilterChain.class);

    }

    @DataProvider(name = "blockedMethods")
    public Object[][] blockedMethods() {
        return new Object[][]{
                {"TRACE","/"},
                {"TRACK","/"},
                {"trace","/"},
                {"track","/"},
                {"TRACE","/zts"},
                {"TRACK","/zts"},
                {"TRACE","/zts/v1/domain"},
                {"TRACK","/zts/v1/domain"},
                {"TRACK","/any/path"}
        };
    }

    @Test(dataProvider = "blockedMethods")
    public void testBlockedMethods(String method, String uri) throws Exception {
        when(mockRequest.getMethod()).thenReturn(method);
        when(mockRequest.getRequestURI()).thenReturn(uri);

        filter.doFilter(mockRequest, mockResponse, mockChain);

        verify(mockResponse).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        verifyNoInteractions(mockChain);
    }

    @DataProvider(name = "allowedMethods")
    public Object[][] allowedMethods() {
        return new Object[][]{
                {"GET"},
                {"POST"},
                {"PUT"},
                {"DELETE"},
                {"PATCH"},
                {"HEAD"},
                {"OPTIONS"}
        };
    }

    @Test(dataProvider = "allowedMethods")
    public void testAllowedMethods(String method) throws Exception {
        when(mockRequest.getMethod()).thenReturn(method);

        filter.doFilter(mockRequest, mockResponse, mockChain);

        verify(mockResponse, never()).setStatus(anyInt());
        verify(mockChain).doFilter(mockRequest, mockResponse);
    }

    @Test
    public void testDestroyNoOp() {
        //destroy() is a no-op, just verify it doesn't throw error
        filter.destroy();
    }
}