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

import org.apache.commons.daemon.Daemon;
import org.apache.commons.daemon.DaemonContext;

public class AthenzDaemon implements Daemon {

    private String[] args = null;

    public void init(DaemonContext context) {
        args = context.getArguments();
    }

    public void start() throws Exception {
        if (args == null) {
            return;
        }
        AthenzJettyContainer.main(args);
    }

    public void stop() throws Exception {
    }

    public void destroy() {
    }
}
