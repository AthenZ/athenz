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
package com.yahoo.athenz.zms;

import static org.testng.Assert.*;

import org.apache.commons.daemon.DaemonContext;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class ZMSDaemonTest {

    @Test
    public void testInit() throws Exception {
        DaemonContext daemoncontext = Mockito.mock(DaemonContext.class);
        ZMSDaemon daemon = new ZMSDaemon();
        daemon.init(daemoncontext);
    }

    @Test
    public void testStart() {
        ZMSDaemon daemon = new ZMSDaemon();
        try {
            daemon.start();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testStop() throws Exception {
        ZMSDaemon daemon = new ZMSDaemon();
        daemon.stop();
    }

    @Test
    public void testDestroy() throws Exception {
        ZMSDaemon daemon = new ZMSDaemon();
        daemon.destroy();
    }
}
