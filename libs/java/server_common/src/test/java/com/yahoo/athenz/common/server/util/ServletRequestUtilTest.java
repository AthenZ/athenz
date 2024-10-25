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
package com.yahoo.athenz.common.server.util;

import jakarta.servlet.http.HttpServletRequest;

import org.eclipse.jetty.http.HttpHeader;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

public class ServletRequestUtilTest {

    @Test
    public void testGetRemoteAddressNoLoopBack() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("1.2.3.4");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "1.2.3.4");
    }
    
    @Test
    public void testGetRemoteAddressNull() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn(null);
        assertNull(ServletRequestUtil.getRemoteAddress(httpServletRequest));
    }
    
    @Test
    public void testGetRemoteAddressLoopBackNoXFF() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
    }
    
    @Test
    public void testGetRemoteAddressLoopBackSingleXFF() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "1.2.3.4");
    }
    
    @Test
    public void testGetRemoteAddressLoopBackMultipleXFF() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 1.3.4.5, 1.4.5.6");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "1.4.5.6");
    }

    @Test
    public void testGetRemoteAddressLoopBackSingleXFFInvalidIP() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn("1.2.300.4")
                .thenReturn("testip").thenReturn(";s=signature");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
    }

    @Test
    public void testGetRemoteAddressLoopBackMultipleXFFInvalidIP() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(httpServletRequest.getHeader("X-Forwarded-For"))
                .thenReturn("1.2.3.4, 1.3.4.5, 1.4.5.600")
                .thenReturn("1.2.3.4, testSTring")
                .thenReturn("1.2.3.4, ;s=signature");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
        assertEquals(ServletRequestUtil.getRemoteAddress(httpServletRequest), "127.0.0.1");
    }

    @Test
    public void testGetSiaAgentWithOutHeader() {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        assertNull(ServletRequestUtil.getSiaProvider(httpServletRequest));
    }

    @Test(dataProvider = "dataGetSiaAgentWithHeader")
    public void testGetSiaAgentWithHeader(String headerValue, String expected) {
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getHeader(HttpHeader.USER_AGENT.asString())).thenReturn(headerValue);
        assertEquals(ServletRequestUtil.getSiaProvider(httpServletRequest), expected);
    }

    @DataProvider
    private Object[][] dataGetSiaAgentWithHeader() {
        List<Object[]> data = new ArrayList<>();
        data.add(new Object[] {null, null});
        data.add(new Object[] {"", null});
        data.add(new Object[] {"    ", null});
        data.add(new Object[] {"SIA-FARGATE 1.32.0", "FARGATE"});
        data.add(new Object[] {"SIA-FARGATE     1.32.0", "FARGATE"});
        data.add(new Object[] {"SIA-FARGATE ", "FARGATE"});
        data.add(new Object[] {"SIA-FARGATE   ", "FARGATE"});
        data.add(new Object[] {"SIA-FARGATE", "FARGATE"});
        // don;t expect tab
        data.add(new Object[] {"SIA-FARGATE\t1.32.0", "FARGATE\t1.32.0"});
        return data.toArray(new Object[0][]);
    }
}
