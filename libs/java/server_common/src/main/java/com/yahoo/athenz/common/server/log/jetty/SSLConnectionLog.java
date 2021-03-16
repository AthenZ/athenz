/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static com.yahoo.athenz.common.ServerCommonConsts.SSL_CONNECTION_LOG_NAME;

public class SSLConnectionLog implements ConnectionLog {

    private JsonConnectionLogWriter jsonConnectionLogWriter = new JsonConnectionLogWriter();
    private static final Logger LOG = LoggerFactory.getLogger(SSL_CONNECTION_LOG_NAME);

    @Override
    public void log(ConnectionLogEntry connectionLogEntry) {
        try {
            LOG.info(jsonConnectionLogWriter.logEntryToString(connectionLogEntry));
        } catch (IOException exception) {
            LOG.error("Failed to write connectionLogEntry. ex: {}", exception);
        }
    }
}
