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
package com.yahoo.athenz.common.server.dns;

import com.yahoo.athenz.zts.CertType;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

public class HostnameResolverTest {

    static class TestHostnameResolver implements HostnameResolver {
    }

    @Test
    public void testHostnameResolverCreate() {

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);

        HostnameResolverFactory factory = () -> resolver;

        HostnameResolver testResolver = factory.create();
        assertNotNull(testResolver);
    }

    @Test
    public void testHostnameResolverCheck() {

        HostnameResolver resolver = new TestHostnameResolver();
        assertTrue(resolver.isValidHostname("host1.athenz.cloud"));
        assertTrue(resolver.isValidHostname("host2.athenz.cloud"));
        assertTrue(resolver.isValidHostname("host3.athenz.cloud"));

        assertNotNull(resolver.getAllByName("host1.athenz.cloud"));

        assertFalse(resolver.isValidHostCnameList("athenz.examples.httpd", "host1.athenz.cloud",
                Collections.singletonList("cname.athenz.cloud"), CertType.X509));
    }
}
