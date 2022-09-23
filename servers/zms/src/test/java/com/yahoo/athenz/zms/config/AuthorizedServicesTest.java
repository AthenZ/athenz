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
package com.yahoo.athenz.zms.config;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertNull;
import java.util.HashMap;

import org.mockito.Mockito;
import org.testng.annotations.Test;

public class AuthorizedServicesTest {

    @Test
    public void testGetServices() {
        AuthorizedServices authorizedService = new AuthorizedServices();
        HashMap<String, AuthorizedService> services = authorizedService.getServices();
        assertNull(services);
    }

    @Test
    public void testSetTemplates() {
        AuthorizedServices authorizedService = new AuthorizedServices();
        @SuppressWarnings("unchecked")
        HashMap<String, AuthorizedService> authorizedServiceHash = Mockito.mock(HashMap.class);
        authorizedService.setTemplates(authorizedServiceHash);
    }

    @Test
    public void testName() {
        AuthorizedServices authorizedService = new AuthorizedServices();
        try {
            authorizedService.names();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

}
