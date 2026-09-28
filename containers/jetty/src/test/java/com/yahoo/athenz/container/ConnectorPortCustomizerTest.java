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
package com.yahoo.athenz.container;

import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.server.Request;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ConnectorPortCustomizerTest {

    @Test
    public void testCustomizeStampsConnectorPort() {
        ConnectorPortCustomizer customizer = new ConnectorPortCustomizer(9443);
        assertEquals(customizer.getPort(), 9443);

        Request request = mock(Request.class);
        HttpFields.Mutable headers = mock(HttpFields.Mutable.class);

        Request result = customizer.customize(request, headers);

        assertSame(result, request);
        verify(request, times(1)).setAttribute(ServletRequestUtil.CONNECTOR_PORT_ATTRIBUTE, 9443);
        verifyNoInteractions(headers);
    }
}
