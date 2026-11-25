/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.pdp;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.RolesProvider;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.testng.Assert.*;

public class ExternalPdpContextTest {

    @Test
    public void testBuilder() throws Exception {
        SSLContext sslContext = SSLContext.getDefault();
        RolesProvider rolesProvider = domainName -> Collections.emptyList();
        PrivateKeyStore keyStore = new PrivateKeyStore() { };
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            ExternalPdpContext context = new ExternalPdpContext.Builder()
                    .endpoint("https://pdp.athenz.io")
                    .sslContext(sslContext)
                    .rolesProvider(rolesProvider)
                    .privateKeyStore(keyStore)
                    .executor(executor)
                    .connectTimeoutMs(100)
                    .readTimeoutMs(200)
                    .maxConnections(8)
                    .build();
            assertEquals(context.getEndpoint(), "https://pdp.athenz.io");
            assertSame(context.getSslContext(), sslContext);
            assertSame(context.getRolesProvider(), rolesProvider);
            assertSame(context.getPrivateKeyStore(), keyStore);
            assertSame(context.getExecutor(), executor);
            assertEquals(context.getConnectTimeoutMs(), 100);
            assertEquals(context.getReadTimeoutMs(), 200);
            assertEquals(context.getMaxConnections(), 8);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void testException() {
        ExternalPdpException ex = new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "slow");
        assertEquals(ex.getCode(), ExternalPdpException.Code.TIMEOUT);
        assertEquals(ex.getMessage(), "slow");
        IllegalStateException cause = new IllegalStateException();
        ex = new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "bad", cause);
        assertSame(ex.getCause(), cause);
        assertEquals(ex.getCode(), ExternalPdpException.Code.INTERNAL);
    }
}
