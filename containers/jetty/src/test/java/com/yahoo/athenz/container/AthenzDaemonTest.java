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

import static org.testng.Assert.*;

import org.apache.commons.daemon.DaemonContext;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class AthenzDaemonTest {

    @Test
    public void testInit() {
        DaemonContext daemoncontext = Mockito.mock(DaemonContext.class);
        AthenzDaemon daemon = new AthenzDaemon();
        daemon.init(daemoncontext);
    }

    @Test
    public void testStart() {
        AthenzDaemon daemon = new AthenzDaemon();
        try {
            daemon.start();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testStop() throws Exception {
        AthenzDaemon daemon = new AthenzDaemon();
        daemon.stop();
    }

    @Test
    public void testDestroy() {
        AthenzDaemon daemon = new AthenzDaemon();
        daemon.destroy();
    }
}
