/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts;

import org.apache.commons.daemon.DaemonContext;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.zts.cert.CertSigner;

public class ZTSDaemonTest {

    @Test
    public void testZTSDaemon() throws Exception {

        ZTSDaemon daemon = new ZTSDaemon();

        DaemonContext ctxMock = Mockito.mock(DaemonContext.class);
        Mockito.when(ctxMock.getArguments()).thenReturn(null);

        daemon.init(ctxMock);

        // nothing to do
        daemon.start();
        daemon.stop();
        daemon.destroy();
    }

    @Test
    public void testZTSGetAuditLogger() {
        AuditLogger logger = ZTS.getAuditLogger();
        assertNotNull(logger);
    }

    @Test
    public void testZTSGetAuthority() {
        assertNull(ZTS.getAuthority("test"));
    }

    @Test
    public void testZTSGetServerHostName() {
        assertNotNull(ZTS.getServerHostName());
    }

    @Test
    public void testZTSGetPortNumber() {

        // default
        assertEquals(ZTS.getPortNumber("unsetproperty", 4080), 4080);

        // set appropriate property
        System.setProperty("testportnum", "4444");
        assertEquals(ZTS.getPortNumber("testportnum", 4080), 4444);

        // set invalid port number -> should set default
        System.setProperty("testportnum", "70000");
        assertEquals(ZTS.getPortNumber("testportnum", 4080), 4080);

    }

    @Test
    public void testZTSGetCertSigner() {
        assertNotNull(ZTS.getCertSigner());
    }

    @Test
    public void testZTSGetInstancIdentityStore() {
        CertSigner signer = ZTS.getCertSigner();

        assertNotNull(ZTS.getInstanceIdentityStore(signer));
    }

    @Test
    public void testZTSGetMetric() {
        assertNotNull(ZTS.getMetric());
    }

    @Test
    public void testZTSGetPrivateKeyStore() {
        assertNotNull(ZTS.getPrivateKeyStore());
    }

}
